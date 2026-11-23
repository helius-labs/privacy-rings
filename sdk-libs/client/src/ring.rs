use std::{collections::HashSet, future::Future};

use solana_address::Address;
use spr_keypair::{shielded::ShieldedAddress, PublicKey, SigningKey, ViewingKey, X25519Pubkey};
use spr_transaction::{
    checked_ring_payment,
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    keys::{DecryptRequest, DeriveRequest, ShieldedKeys, TransactionKeyRequest},
    select_spend_excluding, Mint, RingPaymentTerms, SpendableDecryptionResult, TransactionError,
    WalletUtxo,
};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{field::right_align_slice, transact::OwnerAuthorization, TransferInput},
};

/// Core selects the inputs and binds the change to the ring.
pub trait RingTransfers {
    type Error: From<TransactionError>;
    /// Kept by the caller until it settles, a dropped send resumes from it.
    type Prepared;

    fn ring_program_id(&self) -> Address;

    fn prepare(
        &self,
        request: RingTransferRequest<'_>,
    ) -> impl Future<Output = Result<Self::Prepared, Self::Error>> + Send;
}

/// Funded by default-ring notes, the change stays in the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingPayment {
    pub payer: Address,
    pub recipient: ShieldedAddress,
    pub asset: Mint,
    pub amount: u64,
}

pub struct RingPaymentWallet<'a> {
    pub spendable: &'a SpendableDecryptionResult,
    pub keys: &'a (dyn ShieldedKeys + Sync),
    pub authority: &'a dyn ProofAuthority,
    /// Unset, the wallet trusts the ring for what it proves.
    pub owner: Option<&'a SigningKey>,
    /// Nullifiers of notes held by an unsettled prepared payment.
    pub excluded: &'a HashSet<[u8; 32]>,
}

pub struct RingTransferRequest<'a> {
    pub transaction: ConfidentialTransaction,
    pub payment: RingPayment,
    pub keys: ReservedKeys<'a>,
    pub authorizer: RingAuthorizer<'a>,
}

/// Completing a reserved input hands the ring the wallet's nullifier secret.
pub struct ReservedKeys<'a> {
    keys: &'a (dyn ShieldedKeys + Sync),
    authority: &'a dyn ProofAuthority,
    reserved: &'a [WalletUtxo],
}

pub struct RingAuthorizer<'a> {
    terms: RingPaymentTerms<'a>,
    owner: Option<&'a SigningKey>,
}

impl RingPayment {
    pub async fn prepare<R: RingTransfers>(
        self,
        ring: &R,
        wallet: RingPaymentWallet<'_>,
    ) -> Result<R::Prepared, R::Error> {
        let ring_program_id = ring.ring_program_id();
        let reserved = select_spend_excluding(
            wallet.spendable.utxos(),
            self.asset.asset,
            self.amount,
            wallet.excluded,
        )?;
        let terms = RingPaymentTerms {
            source: wallet.keys.address()?,
            recipient: self.recipient,
            asset: self.asset,
            amount: self.amount,
            ring_program_id,
            reserved: &reserved,
        };
        let request = RingTransferRequest {
            transaction: ConfidentialTransaction::new_with_ring(
                reserved.clone(),
                self.payer,
                ring_program_id,
            )?,
            payment: self,
            keys: ReservedKeys {
                keys: wallet.keys,
                authority: wallet.authority,
                reserved: &reserved,
            },
            authorizer: RingAuthorizer {
                terms,
                owner: wallet.owner,
            },
        };
        ring.prepare(request).await
    }
}

impl RingAuthorizer<'_> {
    pub fn owner(&self) -> Option<PublicKey> {
        self.owner.map(SigningKey::pubkey)
    }

    /// Takes each attempt's final proof inputs before the ring proves them.
    pub fn authorize(
        &self,
        proof_inputs: &SppProofInputs,
    ) -> Result<Option<OwnerAuthorization<'static>>, TransactionError> {
        let checked = checked_ring_payment(proof_inputs, &self.terms)?;
        self.owner
            .map(|owner| {
                Ok(OwnerAuthorization::Prepared {
                    owner: owner.pubkey(),
                    signature: owner.sign_message(&checked.message_hash()?)?,
                })
            })
            .transpose()
    }
}

impl ReservedKeys<'_> {
    fn reserves(&self, nullifier: &[u8; 32]) -> bool {
        self.reserved
            .iter()
            .any(|note| &note.nullifier == nullifier)
    }
}

impl ShieldedKeys for ReservedKeys<'_> {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.keys.address()
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.keys.viewing_public_keys()
    }

    fn decrypt(&self, _: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        Err(TransactionError::RingKeyWithheld)
    }

    fn derive(&self, _: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        Err(TransactionError::RingKeyWithheld)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        if requests
            .iter()
            .all(|request| self.reserves(&request.first_nullifier))
        {
            self.keys.transaction_keys(requests)
        } else {
            Err(TransactionError::RingKeyWithheld)
        }
    }
}

impl ProofAuthority for ReservedKeys<'_> {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        for input in inputs
            .iter()
            .filter(|input| input.nullifier_secret.is_none())
        {
            if !self.reserves(&right_align_slice(&input.nullifier.to_bytes_be())?) {
                return Err(TransactionError::RingKeyWithheld.into());
            }
        }
        self.authority.complete_inputs(inputs)
    }
}
