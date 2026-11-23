use std::{future::ready, sync::Arc};

use p256::elliptic_curve::subtle::ConstantTimeEq;
use solana_pubkey::Pubkey;
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{
    DecryptLabel, DecryptRequest, DeriveRequest, LocalShieldedKeys, ShieldedKeys, TransactionError,
    TransactionKeyRequest,
};
use zeroize::Zeroizing;

use crate::{ClientError, ProofAuthority, TransferInput};

use super::{
    owner_call, NitroDecryptionError, NitroDecryptionService, Owner, MAX_ITEMS, OWNER_TIMEOUT,
};

impl NitroDecryptionService {
    /// Authorize recovery for the owner and check the secret against its published key.
    pub async fn open(
        &self,
        signer: Arc<Owner>,
    ) -> Result<NitroDecryptionKeys, NitroDecryptionError> {
        let owner = {
            let signer = signer.clone();
            owner_call(
                &self.0.owner_work,
                OWNER_TIMEOUT,
                ready(Ok(())),
                move || {
                    signer
                        .try_pubkey()
                        .map_err(|_| NitroDecryptionError::InvalidOwner)
                },
            )
            .await?
        };
        let address = self.address_with_retry(owner, false).await?;
        let (nullifier, _) = self.decrypt_batch(owner, signer.clone(), &[]).await?;
        let transaction_key = local_transaction_key(&nullifier)?;
        if nullifier
            .pubkey()
            .map_err(|_| NitroDecryptionError::Protocol)?
            != address.nullifier_pubkey
        {
            return Err(NitroDecryptionError::Protocol);
        }
        let local = LocalShieldedKeys::new(
            ShieldedAddress {
                viewing_pubkey: transaction_key.pubkey(),
                ..address
            },
            vec![transaction_key],
            nullifier.clone(),
        )
        .map_err(|_| NitroDecryptionError::Protocol)?;
        Ok(NitroDecryptionKeys {
            service: self.clone(),
            signer,
            owner,
            address,
            nullifier,
            local,
        })
    }

    pub fn open_sync(
        &self,
        signer: Arc<Owner>,
    ) -> Result<NitroDecryptionKeys, NitroDecryptionError> {
        self.runtime().block_on(self.open(signer))
    }
}

fn local_transaction_key(nullifier: &NullifierKey) -> Result<ViewingKey, NitroDecryptionError> {
    let mut bytes = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, nullifier.secret().as_ref())
        .expand(b"TSPP/decryption-service/tx_key/v1", bytes.as_mut())
        .map_err(|_| NitroDecryptionError::Protocol)?;
    Ok(ViewingKey::from_bytes(&bytes))
}

/// The owner's service viewing capability and local nullifier authority.
pub struct NitroDecryptionKeys {
    service: NitroDecryptionService,
    signer: Arc<Owner>,
    owner: Pubkey,
    address: ShieldedAddress,
    nullifier: NullifierKey,
    local: LocalShieldedKeys,
}

impl NitroDecryptionKeys {
    /// Opens bounded batches using an owner signature once per batch.
    pub async fn decrypt_async(
        &self,
        requests: &[DecryptRequest<'_>],
    ) -> Result<Vec<Vec<u8>>, NitroDecryptionError> {
        if requests.iter().any(|request| {
            request.viewing_pubkey != self.address.viewing_pubkey
                || (request.label == DecryptLabel::RingDeposit && request.slot_index != 0)
        }) {
            return Err(NitroDecryptionError::Protocol);
        }
        let mut results = Zeroizing::new(Vec::with_capacity(requests.len()));
        let mut remaining = requests;
        while !remaining.is_empty() {
            let mut count = remaining.len().min(MAX_ITEMS);
            loop {
                match self
                    .service
                    .decrypt_batch(self.owner, self.signer.clone(), &remaining[..count])
                    .await
                {
                    Ok((nullifier, mut plaintexts)) => {
                        if !bool::from(self.nullifier.secret().ct_eq(&*nullifier.secret())) {
                            return Err(NitroDecryptionError::Protocol);
                        }
                        results.append(&mut plaintexts);
                        break;
                    }
                    Err(NitroDecryptionError::RequestTooLarge) if count > 1 => count /= 2,
                    Err(error) => return Err(error),
                }
            }
            remaining = &remaining[count..];
        }
        Ok(std::mem::take(&mut *results))
    }
}

impl ShieldedKeys for NitroDecryptionKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.address)
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        vec![self.address.viewing_pubkey]
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.service
            .runtime()
            .block_on(self.decrypt_async(requests))
            .map_err(|error| TransactionError::KeyHolder(error.to_string()))
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        let viewing = self.local.address()?.viewing_pubkey;
        let requests = requests
            .iter()
            .map(|request| {
                if request.viewing_pubkey != self.address.viewing_pubkey {
                    return Err(TransactionError::UnknownViewingKey);
                }
                Ok(TransactionKeyRequest {
                    viewing_pubkey: viewing,
                    ..*request
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.local.transaction_keys(&requests)
    }
}

impl ProofAuthority for NitroDecryptionKeys {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        self.nullifier.complete_inputs(inputs)
    }
}
