use solana_address::Address;
use spr_keypair::{
    constants::SALT_LEN, x25519::X25519_PUBKEY_LEN, EncryptionMode, PublicKey, ViewingKey,
    X25519Pubkey,
};
use wincode::{SchemaRead, SchemaWrite};

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{data::Data, error::TransactionError, utxo::Utxo, AssetRegistry, EncryptedScheme};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialOutputPlaintext {
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub ring_program_id: Option<Address>,
    pub data: Data,
}

impl ConfidentialOutputPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxo(
        self,
        owner: PublicKey,
        assets: &AssetRegistry,
    ) -> Result<Utxo, TransactionError> {
        if self.data.ring_data().is_some() && self.ring_program_id.is_none() {
            return Err(TransactionError::MissingRingProgramId);
        }
        Ok(Utxo {
            owner,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data,
        })
    }
}

pub struct ConfidentialEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: X25519Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct Confidential;

pub(crate) trait ConfidentialCodec {
    const ENCRYPTED_SCHEME: EncryptedScheme;
    const ENCRYPTION_MODE: EncryptionMode;

    fn decrypt_sender(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        let (recipient_pubkey, ciphertext) = split_embedded_pk(body)?;
        let bytes = tx.decrypt_slot_ephemeral_with_mode(
            &recipient_pubkey,
            ciphertext,
            salt,
            slot_index,
            Self::ENCRYPTION_MODE,
        )?;
        ConfidentialOutputPlaintext::deserialize(&bytes)
    }
}

impl ConfidentialCodec for Confidential {
    const ENCRYPTED_SCHEME: EncryptedScheme = EncryptedScheme::Confidential;
    const ENCRYPTION_MODE: EncryptionMode = EncryptionMode::Hkdf;
}

fn split_embedded_pk(body: &[u8]) -> Result<(X25519Pubkey, &[u8]), TransactionError> {
    let (prefix, rest) =
        body.split_at_checked(X25519_PUBKEY_LEN)
            .ok_or(TransactionError::InvalidLength {
                expected: X25519_PUBKEY_LEN,
                actual: body.len(),
            })?;
    let bytes: [u8; X25519_PUBKEY_LEN] =
        prefix
            .try_into()
            .map_err(|_| TransactionError::InvalidLength {
                expected: X25519_PUBKEY_LEN,
                actual: prefix.len(),
            })?;
    Ok((X25519Pubkey::from_bytes(bytes)?, rest))
}

impl Confidential {
    pub fn embedded_viewing_pk(body: &[u8]) -> Result<X25519Pubkey, TransactionError> {
        Ok(split_embedded_pk(body)?.0)
    }

    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        Self::decrypt_sender(tx, body, salt, slot_index)
    }
}

impl<C: ConfidentialCodec> UtxoSerialization for C {
    const SCHEME: EncryptedScheme = C::ENCRYPTED_SCHEME;
    type Plaintext = ConfidentialOutputPlaintext;
    type EncodeCx = ConfidentialEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        let (recipient_pubkey, ciphertext) = split_embedded_pk(body)?;
        if C::ENCRYPTION_MODE == EncryptionMode::PoseidonKdf
            && recipient_pubkey != cx.viewing_key.pubkey()
        {
            return Err(TransactionError::RecipientViewingKeyMismatch);
        }
        Ok(cx.viewing_key.decrypt_utxo_with_mode(
            ciphertext,
            &tx_viewing_pk,
            salt,
            cx.slot_index,
            C::ENCRYPTION_MODE,
        )?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        ConfidentialOutputPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Ok(vec![plaintext.into_utxo(cx.owner, cx.assets)?])
    }

    fn from_utxos(
        utxos: &[Utxo],
        _: &OwnerCx,
        _cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        Ok(ConfidentialOutputPlaintext {
            asset_id: first.asset.asset_id,
            amount: first.amount,
            blinding: first.blinding,
            ring_program_id: first.ring_program_id,
            data: first.data.clone(),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        let ciphertext = cx.tx.encrypt_slot_with_mode(
            &cx.recipient_pubkey,
            bytes,
            cx.salt,
            cx.slot_index,
            C::ENCRYPTION_MODE,
        )?;
        let mut body = Vec::with_capacity(X25519_PUBKEY_LEN + ciphertext.len());
        body.extend_from_slice(cx.recipient_pubkey.as_bytes());
        body.extend_from_slice(&ciphertext);
        Ok(body)
    }
}
