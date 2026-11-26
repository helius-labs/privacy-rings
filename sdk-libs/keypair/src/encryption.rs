use aes::Aes256;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr32BE,
};
use spr_hasher::primitives::{pack_be, right_align};
use zeroize::Zeroizing;

use crate::{
    constants::{CTR_NONCE_LEN, SALT_LEN},
    derivation::{
        hkdf_expand, DOMAIN_VERIFIABLE_TRANSCRIPT, DOM_SEP_KEY, DOM_SEP_NONCE, DOM_SEP_SILO,
        ENC_INFO_RING_DEPOSIT, ENC_INFO_TRANSFER, ENC_INFO_VERIFIABLE, HPKE_PREFIX,
    },
    error::KeypairError,
    hash::poseidon,
    x25519::{X25519Keypair, X25519Pubkey, X25519_PUBKEY_LEN},
};

type Aes256Ctr = Ctr32BE<Aes256>;

/// Per-output encryption for confidential transactions. Both modes use X25519
/// and AES-256-CTR; verifiable mode uses the circuit-compatible Poseidon KDF.
/// The application proof must separately enforce correct encryption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncryptionMode {
    #[default]
    Confidential,
    /// Poseidon/AES version 1. Pack the ECDH bytes and both tagged public keys
    /// independently with `pack_be` (31-byte big-endian chunks). Hash, in order:
    /// `TVE1, shared[0], shared[1], tx_pk[0], tx_pk[1], recipient_pk[0],
    /// recipient_pk[1], right_align(salt), right_align(u32_be(slot_index))`.
    /// Feed that secret and `ENC_INFO_VERIFIABLE` into `symmetric_apply`.
    /// AES-256-CTR starts at the derived 12-byte nonce followed by `u32_be(2)`.
    Verifiable,
}

/// A fixed transcript packs each byte string in 31-byte chunks, preserving
/// X25519's little-endian encodings without reducing them modulo BN254 Fr.
/// Public keys, fresh transaction salt and physical output index are bound
/// before the existing symmetric key schedule. "TVE1" versions the transcript.
fn verifiable_apply(
    shared_secret: &[u8; 32],
    ephemeral_pubkey: &X25519Pubkey,
    recipient_pubkey: &X25519Pubkey,
    salt: &[u8; SALT_LEN],
    slot: u32,
    ciphertext: &mut [u8],
) -> Result<(), KeypairError> {
    let shared = Zeroizing::new(pack_be::<32, 2>(shared_secret));
    let ephemeral = pack_be::<33, 2>(ephemeral_pubkey.as_bytes());
    let recipient = pack_be::<33, 2>(recipient_pubkey.as_bytes());
    let transcript_secret = Zeroizing::new(poseidon(&[
        &right_align(&DOMAIN_VERIFIABLE_TRANSCRIPT.to_be_bytes()),
        &shared[0],
        &shared[1],
        &ephemeral[0],
        &ephemeral[1],
        &recipient[0],
        &recipient[1],
        &right_align(salt),
        &right_align(&slot.to_be_bytes()),
    ])?);
    symmetric_apply(&transcript_secret, ENC_INFO_VERIFIABLE, ciphertext)
}

pub(crate) struct UtxoCipher<'a> {
    pub mode: EncryptionMode,
    pub ephemeral_pubkey: &'a X25519Pubkey,
    pub recipient_pubkey: &'a X25519Pubkey,
    pub salt: &'a [u8; SALT_LEN],
    pub slot: u32,
}

impl UtxoCipher<'_> {
    pub fn apply(
        self,
        secret_key: &X25519Keypair,
        counterparty: &X25519Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        let shared = secret_key.ecdh(counterparty)?;
        let mut output = ciphertext.to_vec();
        match self.mode {
            EncryptionMode::Confidential => {
                let (key, nonce) = derive_key_nonce(
                    &shared,
                    self.ephemeral_pubkey,
                    self.recipient_pubkey,
                    ENC_INFO_TRANSFER,
                    self.salt,
                    self.slot,
                )?;
                ctr_apply(&key, &nonce, &mut output);
            }
            EncryptionMode::Verifiable => {
                verifiable_apply(
                    &shared,
                    self.ephemeral_pubkey,
                    self.recipient_pubkey,
                    self.salt,
                    self.slot,
                    &mut output,
                )?;
            }
        }
        Ok(output)
    }
}

/// AES-256-CTR matching aes/ctr.go: J0 = nonce || 0x00000001 and the counter is
/// advanced once before the first block, so encryption starts at nonce || 2.
/// Used for transfer and merge ciphertexts (no authentication tag; integrity
/// comes from proof-committed hashes).
pub(crate) fn ctr_apply(key: &[u8; 32], nonce: &[u8; CTR_NONCE_LEN], buf: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..CTR_NONCE_LEN].copy_from_slice(nonce);
    iv[15] = 2;
    let mut cipher = Aes256Ctr::new(key.into(), (&iv).into());
    cipher.apply_keystream(buf);
}

fn key_schedule(
    shared_secret: &[u8; 32],
    info: &[u8; 10],
) -> Result<([u8; 32], [u8; CTR_NONCE_LEN]), KeypairError> {
    let [info_field] = pack_be::<10, 1>(info);
    let siloed = poseidon(&[
        &right_align(&DOM_SEP_SILO.to_be_bytes()),
        shared_secret,
        &info_field,
    ])?;
    let key_lo = poseidon(&[&right_align(&DOM_SEP_KEY.to_be_bytes()), &siloed])?;
    let key_hi = poseidon(&[&right_align(&(DOM_SEP_KEY + 1).to_be_bytes()), &siloed])?;
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&key_hi[16..32]);
    key[16..32].copy_from_slice(&key_lo[16..32]);
    let nonce_raw = poseidon(&[&right_align(&DOM_SEP_NONCE.to_be_bytes()), &siloed])?;
    let mut nonce = [0u8; CTR_NONCE_LEN];
    nonce.copy_from_slice(&nonce_raw[20..32]);
    Ok((key, nonce))
}

/// Symmetric verifiable encryption: derive the AES-256-CTR key/nonce from a
/// pre-shared `shared_secret` via the same Poseidon key schedule as the
/// circuit's `KeySchedule` + `CTREncrypt`, then apply the keystream.
/// Encryption and decryption are the same operation.
///
/// The key and nonce are fully determined by `(shared_secret, info)`, so the
/// caller must never encrypt two different plaintexts under one pair: CTR
/// keystream reuse leaks their XOR.
pub fn symmetric_apply(
    shared_secret: &[u8; 32],
    info: &[u8; 10],
    buf: &mut [u8],
) -> Result<(), KeypairError> {
    let (key, nonce) = key_schedule(shared_secret, info)?;
    let key = Zeroizing::new(key);
    ctr_apply(&key, &nonce, buf);
    Ok(())
}

fn derive_key_nonce(
    dh: &[u8; 32],
    ephemeral_pubkey: &X25519Pubkey,
    recipient_pubkey: &X25519Pubkey,
    info: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; CTR_NONCE_LEN]), KeypairError> {
    let mut ikm = Zeroizing::new([0u8; 32 + 2 * X25519_PUBKEY_LEN]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..32 + X25519_PUBKEY_LEN].copy_from_slice(ephemeral_pubkey.as_bytes());
    ikm[32 + X25519_PUBKEY_LEN..].copy_from_slice(recipient_pubkey.as_bytes());

    let mut okm = Zeroizing::new([0u8; 32 + CTR_NONCE_LEN]);
    hkdf_expand(
        None,
        ikm.as_slice(),
        &[HPKE_PREFIX, info, salt, &slot.to_be_bytes()],
        okm.as_mut_slice(),
    )?;
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; CTR_NONCE_LEN];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

pub(crate) fn encrypt_ring_deposit(
    ephemeral_secret_key: &X25519Keypair,
    recipient_pubkey: &X25519Pubkey,
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, KeypairError> {
    encrypt_payload(
        ephemeral_secret_key,
        recipient_pubkey,
        plaintext,
        salt,
        0,
        ENC_INFO_RING_DEPOSIT,
    )
}

fn encrypt_payload(
    ephemeral_secret_key: &X25519Keypair,
    recipient_pubkey: &X25519Pubkey,
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
    info: &[u8],
) -> Result<Vec<u8>, KeypairError> {
    let ephemeral_pubkey = ephemeral_secret_key.pubkey();
    let dh = ephemeral_secret_key.ecdh(recipient_pubkey)?;
    let (key, nonce) =
        derive_key_nonce(&dh, &ephemeral_pubkey, recipient_pubkey, info, salt, slot)?;
    let mut buf = plaintext.to_vec();
    ctr_apply(&key, &nonce, &mut buf);
    Ok(buf)
}

pub(crate) fn decrypt_ring_deposit(
    viewing_secret_key: &X25519Keypair,
    ephemeral_pubkey: &X25519Pubkey,
    ciphertext: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, KeypairError> {
    decrypt_payload(
        viewing_secret_key,
        ephemeral_pubkey,
        ciphertext,
        salt,
        0,
        ENC_INFO_RING_DEPOSIT,
    )
}

fn decrypt_payload(
    viewing_secret_key: &X25519Keypair,
    ephemeral_pubkey: &X25519Pubkey,
    ciphertext: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
    info: &[u8],
) -> Result<Vec<u8>, KeypairError> {
    let recipient_pubkey = viewing_secret_key.pubkey();
    let dh = viewing_secret_key.ecdh(ephemeral_pubkey)?;
    let (key, nonce) =
        derive_key_nonce(&dh, ephemeral_pubkey, &recipient_pubkey, info, salt, slot)?;
    let mut buf = ciphertext.to_vec();
    ctr_apply(&key, &nonce, &mut buf);
    Ok(buf)
}
