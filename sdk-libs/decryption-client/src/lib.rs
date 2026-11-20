//! Verify a Turnkey deployment through Gatekeeper and open its shielded notes.

mod gateway;

use anyhow::{anyhow, ensure, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use solana_signer::Signer;
use spr_client::{ProofAuthority, TransferInput};
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{
    DecryptRequest, DeriveRequest, LocalShieldedKeys, ShieldedKeys, TransactionError,
    TransactionKeyRequest,
};
use spr_tvc_protocol::constants::MAX_ITEMS_PER_BATCH;
use zeroize::Zeroizing;

pub use gateway::{DecryptionClient, ReleasePin};
pub use spr_tvc_protocol::Network;

const TRANSACTION_KEY_LABEL: &[u8] = b"TSPP/decryption-service/tx_key/v1";

impl DecryptionClient {
    /// Looks up registered keys before querying the verified service.
    pub fn resolve_recipient<R: spr_client::Rpc>(
        &self,
        rpc: &R,
        owner: solana_address::Address,
    ) -> Result<ShieldedAddress, spr_client::ClientError> {
        spr_client::user_registry::resolve_shielded_recipient(rpc, owner, |owner| {
            self.public_keys(owner).map_err(|_| {
                spr_client::ClientError::AddressResolution(
                    "could not verify the recipient's decryption service address".into(),
                )
            })
        })
    }

    /// Opens the service identity even when the signer has since registered a local wallet.
    pub fn open<'a>(&'a self, owner: &'a (dyn Signer + Send + Sync)) -> Result<ServiceKeys<'a>> {
        let address = self.public_keys(owner.try_pubkey()?)?;
        let response = self.decrypt(owner, Vec::new())?;
        let nullifier = NullifierKey::from_secret(response.nullifier_secret);
        ensure!(
            nullifier.pubkey()? == address.nullifier_pubkey,
            "the bootstrap response returned a different nullifier key"
        );
        let mut seed = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &response.nullifier_secret)
            .expand(TRANSACTION_KEY_LABEL, seed.as_mut_slice())
            .map_err(|_| anyhow!("derive the service transaction key"))?;
        let viewing = ViewingKey::from_bytes(&seed);
        let transaction_key = viewing.pubkey();
        let local = LocalShieldedKeys::new(
            ShieldedAddress {
                viewing_pubkey: transaction_key,
                ..address
            },
            vec![viewing],
            nullifier.clone(),
        )?;
        Ok(ServiceKeys {
            client: self,
            owner,
            address,
            local,
            transaction_key,
            nullifier,
        })
    }
}

/// Wallet keys for notes sent to the service identity. Open a separate wallet
/// with registered keys for notes addressed to the on-chain registry record.
pub struct ServiceKeys<'a> {
    client: &'a DecryptionClient,
    owner: &'a (dyn Signer + Send + Sync),
    address: ShieldedAddress,
    local: LocalShieldedKeys,
    transaction_key: X25519Pubkey,
    nullifier: NullifierKey,
}

impl ShieldedKeys for ServiceKeys<'_> {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.address)
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        vec![self.address.viewing_pubkey]
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        if requests
            .iter()
            .any(|request| request.viewing_pubkey != self.address.viewing_pubkey)
        {
            return Err(TransactionError::UnknownViewingKey);
        }
        let mut plaintexts = Zeroizing::new(Vec::with_capacity(requests.len()));
        for batch in requests.chunks(MAX_ITEMS_PER_BATCH as usize) {
            let mut result = self
                .client
                .decrypt(
                    self.owner,
                    batch.iter().map(gateway::decrypt_item).collect(),
                )
                .map_err(|_| {
                    TransactionError::Authority("decryption service rejected the batch".into())
                })?;
            if NullifierKey::from_secret(result.nullifier_secret).pubkey()?
                != self.address.nullifier_pubkey
            {
                return Err(TransactionError::Authority(
                    "the decryption service returned a different nullifier key".into(),
                ));
            }
            plaintexts.append(&mut result.plaintexts);
        }
        Ok(std::mem::take(&mut *plaintexts))
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        let translated = requests
            .iter()
            .map(|request| TransactionKeyRequest {
                viewing_pubkey: self.transaction_key,
                first_nullifier: request.first_nullifier,
            })
            .collect::<Vec<_>>();
        self.local.transaction_keys(&translated)
    }
}

impl ProofAuthority for ServiceKeys<'_> {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), spr_client::ClientError> {
        self.nullifier.complete_inputs(inputs)
    }
}
