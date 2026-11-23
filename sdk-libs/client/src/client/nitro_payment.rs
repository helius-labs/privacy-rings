use futures::future::try_join_all;
use solana_hash::Hash;
use solana_keypair::Signer;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_keypair::ShieldedAddress;

use crate::{
    nitro_decryption::{NitroDecryptionError, NitroDecryptionService},
    rpc::{sign_transaction, AsyncRpc},
    ClientError,
};

use super::{
    transaction::send_signed, AsyncIndexer, AsyncSprClient, BlockingIndexer, BlockingRpc,
    SprClient, Submission, UnsignedMessage,
};

/// A resolved payment recipient that retains the lookup for the final policy check.
pub struct NitroPaymentRecipient {
    service: NitroDecryptionService,
    owner: Pubkey,
    address: ShieldedAddress,
}

impl NitroPaymentRecipient {
    pub(crate) fn new(
        service: NitroDecryptionService,
        owner: Pubkey,
        address: ShieldedAddress,
    ) -> Self {
        Self {
            service,
            owner,
            address,
        }
    }

    /// Use these keys to prepare the transaction output, then attach this recipient to its submission.
    pub fn address(&self) -> ShieldedAddress {
        self.address
    }

    async fn revalidate<R: AsyncRpc>(&self, rpc: &R) -> Result<bool, ClientError> {
        let (address, from_service) = self
            .service
            .resolve_recipient_address(rpc, self.owner)
            .await?;
        if address != self.address {
            return Err(NitroDecryptionError::PaymentRecipientChanged.into());
        }
        Ok(from_service)
    }
}

/// A single submission attempt with resolved Nitro recipients checked at the send boundary.
pub struct NitroPaymentSubmission<'a> {
    submission: Submission<'a>,
    recipients: &'a [NitroPaymentRecipient],
}

/// A signed payment whose transaction ID is available before broadcast.
pub struct SignedNitroPayment<'a> {
    recipients: &'a [NitroPaymentRecipient],
    transaction: VersionedTransaction,
    signature: Signature,
    last_valid_block_height: u64,
}

impl<'a> Submission<'a> {
    /// Attach each resolved recipient. All outputs for each attached owner must use the resolved keys.
    pub fn with_nitro_recipients(
        self,
        recipients: &'a [NitroPaymentRecipient],
    ) -> Result<NitroPaymentSubmission<'a>, ClientError> {
        if recipients.is_empty() {
            return Err(NitroDecryptionError::PaymentRecipientsRequired.into());
        }
        for recipient in recipients {
            let mut matches = self
                .signed
                .transaction
                .output_utxos
                .iter()
                .filter_map(|output| output.owner_address)
                .filter(|address| address.signing_pubkey == recipient.address.signing_pubkey)
                .peekable();
            if matches.peek().is_none() || matches.any(|address| address != recipient.address) {
                return Err(NitroDecryptionError::PaymentRecipientMismatch.into());
            }
        }
        Ok(NitroPaymentSubmission {
            submission: self,
            recipients,
        })
    }
}

impl<'a> NitroPaymentSubmission<'a> {
    /// Prove and sign the payment. Broadcast is a separate step.
    pub async fn sign<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncSprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<SignedNitroPayment<'a>, ClientError> {
        self.sign_with(client, async |unsigned: &UnsignedMessage| {
            sign_transaction(unsigned.message.clone(), signers)
        })
        .await
    }

    /// Verify a completed transaction from an external signer against the prepared message.
    pub async fn sign_with<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncSprClient<R, I>,
        sign: impl AsyncFnOnce(&UnsignedMessage) -> Result<VersionedTransaction, ClientError>,
    ) -> Result<SignedNitroPayment<'a>, ClientError> {
        let unsigned = self.submission.finish_unsigned(client).await?;
        self.sign_unsigned(unsigned, sign).await
    }

    async fn sign_unsigned(
        self,
        unsigned: UnsignedMessage,
        sign: impl AsyncFnOnce(&UnsignedMessage) -> Result<VersionedTransaction, ClientError>,
    ) -> Result<SignedNitroPayment<'a>, ClientError> {
        let signed = sign(&unsigned).await?;
        if signed.message != unsigned.message {
            return Err(NitroDecryptionError::PaymentMessageChanged.into());
        }
        signed
            .sanitize()
            .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
        signed
            .verify_and_hash_message()
            .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
        let signature = signed.signatures.first().copied().ok_or_else(|| {
            ClientError::SolanaTransactionSigning("missing fee payer signature".into())
        })?;
        Ok(SignedNitroPayment {
            recipients: self.recipients,
            transaction: signed,
            signature,
            last_valid_block_height: unsigned.last_valid_block_height,
        })
    }

    /// Blocking version of [`Self::sign_with`].
    pub fn sign_with_sync<R: BlockingRpc, I: BlockingIndexer>(
        self,
        client: &SprClient<R, I>,
        sign: impl FnOnce(&UnsignedMessage) -> Result<VersionedTransaction, ClientError>,
    ) -> Result<SignedNitroPayment<'a>, ClientError> {
        client.block_on(self.sign_with(&client.client, async move |unsigned| sign(unsigned)))
    }

    /// Blocking version of [`Self::sign`].
    pub fn sign_sync<R: BlockingRpc, I: BlockingIndexer>(
        self,
        client: &SprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<SignedNitroPayment<'a>, ClientError> {
        client.block_on(self.sign(&client.client, signers))
    }
}

impl SignedNitroPayment<'_> {
    /// Transaction ID to record before sending, for reconciliation after interruption.
    pub fn signature(&self) -> Signature {
        self.signature
    }

    /// Exact recent blockhash in the signed message.
    pub fn blockhash(&self) -> &Hash {
        self.transaction.message.recent_blockhash()
    }

    /// Last valid block height reported alongside the blockhash during preparation.
    pub fn last_valid_block_height(&self) -> u64 {
        self.last_valid_block_height
    }

    /// Check the blockhash and recipients, then make one send and confirmation attempt.
    /// Failures after entering the RPC send path carry the ID in [`ClientError::NitroPaymentSend`].
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncSprClient<R, I>,
    ) -> Result<Signature, ClientError> {
        if !client.rpc().is_blockhash_valid(self.blockhash()).await? {
            return Err(NitroDecryptionError::PaymentBlockhashInvalid.into());
        }
        self.revalidate(client.rpc()).await?;
        send_signed(client, self.transaction)
            .await
            .map_err(|source| ClientError::NitroPaymentSend {
                signature: self.signature,
                source: Box::new(source),
            })
    }

    async fn revalidate<R: AsyncRpc>(&self, rpc: &R) -> Result<(), ClientError> {
        let from_service = try_join_all(
            self.recipients
                .iter()
                .map(|recipient| recipient.revalidate(rpc)),
        )
        .await?;
        let genesis = rpc.genesis_hash().await?;
        for recipient in self.recipients {
            recipient.service.require_chain(genesis)?;
        }
        // Payment policy can change while the final Solana RPC is in flight.
        try_join_all(
            self.recipients
                .iter()
                .zip(from_service)
                .filter(|(_, from_service)| *from_service)
                .map(|(recipient, _)| {
                    recipient
                        .service
                        .confirm_payment_address(recipient.owner, recipient.address)
                }),
        )
        .await?;
        Ok(())
    }

    /// Blocking version of [`Self::send`].
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(
        self,
        client: &SprClient<R, I>,
    ) -> Result<Signature, ClientError> {
        client.block_on(self.send(&client.client))
    }
}

#[cfg(test)]
#[path = "../../tests/nitro_payment.rs"]
mod tests;
