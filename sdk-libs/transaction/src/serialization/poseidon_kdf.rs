//! Confidential plaintext with the Poseidon KDF and AES-256-CTR.
//! The KDF selects encryption only; it does not establish proof verification.

use spr_keypair::{constants::SALT_LEN, EncryptionMode, ViewingKey};

use super::confidential::{ConfidentialCodec, ConfidentialOutputPlaintext};
use crate::{EncryptedScheme, TransactionError};

/// Ordinary `Encrypted(9 || recipient_viewing_pk || ciphertext)` framing.
pub struct PoseidonKdf;

impl ConfidentialCodec for PoseidonKdf {
    const ENCRYPTED_SCHEME: EncryptedScheme = EncryptedScheme::PoseidonKdf;
    const ENCRYPTION_MODE: EncryptionMode = EncryptionMode::PoseidonKdf;
}

impl PoseidonKdf {
    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        Self::decrypt_sender(tx, body, salt, slot_index)
    }
}
