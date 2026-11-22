use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm,
};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{sec1::ToSec1Point, Generate},
    PublicKey,
};
use rand_core::{OsRng, TryRngCore};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use super::NitroDecryptionError;

const NONCE_BYTES: usize = 12;
pub(super) const POINT_BYTES: usize = 65;
const POINT_END: usize = NONCE_BYTES + POINT_BYTES;
const HEADER_BYTES: usize = POINT_END + 4;
const TAG_BYTES: usize = 16;
pub(super) const OVERHEAD: usize = HEADER_BYTES + TAG_BYTES;

pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N], NitroDecryptionError> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| NitroDecryptionError::Random)?;
    Ok(bytes)
}

pub(super) fn parse_point(bytes: &[u8]) -> Result<PublicKey, NitroDecryptionError> {
    if bytes.len() != POINT_BYTES || bytes[0] != 4 {
        return Err(NitroDecryptionError::Protocol);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| NitroDecryptionError::Protocol)
}

pub(super) fn response_secret() -> Result<EphemeralSecret, NitroDecryptionError> {
    EphemeralSecret::try_generate().map_err(|_| NitroDecryptionError::Random)
}

pub(super) fn seal(
    receiver: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, NitroDecryptionError> {
    let ephemeral = response_secret()?;
    let nonce = random_bytes()?;
    seal_with(
        &ephemeral.public_key(),
        receiver,
        ephemeral.diffie_hellman(receiver).raw_secret_bytes(),
        plaintext,
        nonce,
    )
}

fn seal_with(
    sender: &PublicKey,
    receiver: &PublicKey,
    shared: &[u8],
    plaintext: &[u8],
    nonce: [u8; NONCE_BYTES],
) -> Result<Vec<u8>, NitroDecryptionError> {
    let (cipher, aad) = cipher(sender, receiver, shared)?;
    let encrypted = cipher
        .encrypt(
            &Nonce::<Aes256Gcm>::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| NitroDecryptionError::Protocol)?;
    let length =
        u32::try_from(encrypted.len()).map_err(|_| NitroDecryptionError::RequestTooLarge)?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + encrypted.len());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(sender.to_sec1_point(false).as_bytes());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

pub(super) fn open(
    receiver: &EphemeralSecret,
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NitroDecryptionError> {
    let sender = frame_sender(frame)?;
    let shared = receiver.diffie_hellman(&sender);
    open_with(
        &sender,
        &receiver.public_key(),
        shared.raw_secret_bytes(),
        frame,
    )
}

fn frame_sender(frame: &[u8]) -> Result<PublicKey, NitroDecryptionError> {
    if frame.len() < OVERHEAD
        || frame.len() - HEADER_BYTES
            != u32::from_le_bytes(
                frame[POINT_END..HEADER_BYTES]
                    .try_into()
                    .map_err(|_| NitroDecryptionError::Protocol)?,
            ) as usize
    {
        return Err(NitroDecryptionError::Protocol);
    }
    parse_point(&frame[NONCE_BYTES..POINT_END])
}

fn open_with(
    sender: &PublicKey,
    receiver: &PublicKey,
    shared: &[u8],
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NitroDecryptionError> {
    let (cipher, aad) = cipher(sender, receiver, shared)?;
    cipher
        .decrypt(
            Nonce::<Aes256Gcm>::from_slice(&frame[..NONCE_BYTES]),
            Payload {
                msg: &frame[HEADER_BYTES..],
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| NitroDecryptionError::Protocol)
}

fn cipher(
    sender: &PublicKey,
    receiver: &PublicKey,
    shared: &[u8],
) -> Result<(Aes256Gcm, [u8; 2 * (POINT_BYTES + 1)]), NitroDecryptionError> {
    // The protocol uses uncompressed SEC1 points even when a crate defaults to compressed.
    let sender = sender.to_sec1_point(false);
    let sender = sender.as_bytes();
    let receiver = receiver.to_sec1_point(false);
    let receiver = receiver.as_bytes();
    let mut preimage = Zeroizing::new([0; 2 * POINT_BYTES + 32]);
    preimage[..POINT_BYTES].copy_from_slice(sender);
    preimage[POINT_BYTES..2 * POINT_BYTES].copy_from_slice(receiver);
    preimage[2 * POINT_BYTES..].copy_from_slice(shared);
    let mut hmac = <Hmac<Sha512> as Mac>::new_from_slice(&*preimage)
        .map_err(|_| NitroDecryptionError::Protocol)?;
    hmac.update(b"qos_encryption_hmac_message");
    let mut key = hmac.finalize().into_bytes();
    let cipher = Aes256Gcm::new_from_slice(&key[..32]).map_err(|_| NitroDecryptionError::Protocol);
    key.as_mut_slice().zeroize();

    let mut aad = [POINT_BYTES as u8; 2 * (POINT_BYTES + 1)];
    aad[..POINT_BYTES].copy_from_slice(sender);
    aad[POINT_BYTES + 1..2 * POINT_BYTES + 1].copy_from_slice(receiver);
    Ok((cipher?, aad))
}

#[cfg(test)]
#[path = "../../tests/nitro_envelope.rs"]
pub(super) mod tests;
