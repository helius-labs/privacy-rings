//! Confidential UTXO layout encrypted with the Poseidon KDF and AES-256-CTR.
//! The producing application's proof is responsible for verifying encryption.

use spr_keypair::{x25519::X25519_PUBKEY_LEN, EncryptionMode, ViewingKey};

use super::{
    confidential::{
        split_embedded_pk, Confidential, ConfidentialEncode, ConfidentialOutputPlaintext,
    },
    DecodeCx, OwnerCx, UtxoSerialization,
};
use crate::{EncryptedScheme, TransactionError, Utxo};

/// `VerifiablyEncrypted(9 || recipient_viewing_pk || ciphertext)`, with the
/// same plaintext and transaction context as [`Confidential`].
pub struct Verifiable;

impl Verifiable {
    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; 16],
        slot_index: u32,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        let (recipient_pubkey, ciphertext) = split_embedded_pk(body)?;
        let bytes = tx.decrypt_slot_ephemeral_with_mode(
            &recipient_pubkey,
            ciphertext,
            salt,
            slot_index,
            EncryptionMode::Verifiable,
        )?;
        ConfidentialOutputPlaintext::deserialize(&bytes)
    }
}

impl UtxoSerialization for Verifiable {
    const SCHEME: EncryptedScheme = EncryptedScheme::Verifiable;
    type Plaintext = ConfidentialOutputPlaintext;
    type EncodeCx = ConfidentialEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        let (recipient_pubkey, ciphertext) = split_embedded_pk(body)?;
        if recipient_pubkey != cx.viewing_key.pubkey() {
            return Err(TransactionError::RecipientViewingKeyMismatch);
        }
        Ok(cx.viewing_key.decrypt_utxo_with_mode(
            ciphertext,
            &tx_viewing_pk,
            salt,
            cx.slot_index,
            EncryptionMode::Verifiable,
        )?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        Confidential::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Confidential::into_utxos(plaintext, cx)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        Confidential::from_utxos(utxos, owner, cx)
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        Confidential::serialize(plaintext)
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        let ciphertext = cx.tx.encrypt_slot_with_mode(
            &cx.recipient_pubkey,
            bytes,
            cx.salt,
            cx.slot_index,
            EncryptionMode::Verifiable,
        )?;
        let mut body = Vec::with_capacity(X25519_PUBKEY_LEN + ciphertext.len());
        body.extend_from_slice(cx.recipient_pubkey.as_bytes());
        body.extend_from_slice(&ciphertext);
        Ok(body)
    }
}
