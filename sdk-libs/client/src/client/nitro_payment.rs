use futures::future::try_join_all;
use solana_keypair::Signer;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
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

    async fn revalidate<R: AsyncRpc>(&self, rpc: &R) -> Result<(), ClientError> {
        if self
            .service
            .resolve_recipient_address(rpc, self.owner)
            .await?
            != self.address
        {
            return Err(NitroDecryptionError::PaymentRecipientChanged.into());
        }
        Ok(())
    }
}

/// A private transaction with resolved Nitro payment recipients checked at the send boundary.
pub struct NitroPaymentSubmission<'a> {
    submission: Submission<'a>,
    recipients: &'a [NitroPaymentRecipient],
}

impl<'a> Submission<'a> {
    /// Attach each resolved recipient. All outputs for each attached owner must use the resolved keys.
    pub fn with_nitro_recipients(
        self,
        recipients: &'a [NitroPaymentRecipient],
    ) -> Result<NitroPaymentSubmission<'a>, ClientError> {
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

impl NitroPaymentSubmission<'_> {
    /// Prove the transaction and recheck its recipients before returning it for external signing.
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        let unsigned = self.submission.finish_unsigned(client).await?;
        self.revalidate(client.rpc()).await?;
        Ok(unsigned)
    }

    /// Prove, sign, recheck the recipients, then submit and confirm.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let unsigned = self.submission.finish_unsigned(client).await?;
        self.send_unsigned(client, unsigned, signers).await
    }

    async fn send_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        unsigned: UnsignedMessage,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let signed = sign_transaction(unsigned.message, signers)?;
        self.revalidate(client.rpc()).await?;
        send_signed(client, signed).await
    }

    async fn revalidate<R: AsyncRpc>(&self, rpc: &R) -> Result<(), ClientError> {
        try_join_all(
            self.recipients
                .iter()
                .map(|recipient| recipient.revalidate(rpc)),
        )
        .await?;
        Ok(())
    }

    /// See [`Self::finish_unsigned`].
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        client.block_on(self.finish_unsigned(&client.client))
    }

    /// See [`Self::send`].
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        client.block_on(self.send(&client.client, signers))
    }
}

#[cfg(test)]
#[path = "../../tests/nitro_payment.rs"]
mod tests;
