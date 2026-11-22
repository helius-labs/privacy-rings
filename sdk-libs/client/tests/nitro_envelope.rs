use p256::{ecdh::diffie_hellman, SecretKey};
use serde_json::Value;

use super::*;

#[test]
fn seals_the_pinned_qos_envelope() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/qos-borsh-envelope.json")).unwrap();
    let bytes = |field: &str| hex::decode(fixture[field].as_str().unwrap()).unwrap();
    let secret = SecretKey::from_slice(&bytes("ephemeral_secret")).unwrap();
    let receiver = parse_point(&bytes("receiver_encryption_public")).unwrap();
    let plaintext = bytes("plaintext");
    let shared = diffie_hellman(secret.to_nonzero_scalar(), receiver.as_affine());
    let ciphertext = seal_with(
        &secret.public_key(),
        &receiver,
        shared.raw_secret_bytes(),
        &plaintext,
        bytes("nonce").try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(ciphertext, bytes("envelope"));
}

#[test]
fn opens_a_typescript_response_and_rejects_wrong_keys_and_corrupted_frames() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/nitro-exchange.json")).unwrap();
    let ciphertext = hex::decode(fixture["reply"]["encrypted_result"].as_str().unwrap()).unwrap();
    let receiver = SecretKey::from_slice(&[15; 32]).unwrap();
    let result: Value =
        serde_json::from_slice(&open_test_request(&receiver, &ciphertext).unwrap()).unwrap();
    assert_eq!(result, fixture["result"]);
    assert!(open_test_request(&SecretKey::from_slice(&[16; 32]).unwrap(), &ciphertext).is_err());
    for offset in [
        0,
        NONCE_BYTES,
        POINT_END,
        HEADER_BYTES,
        ciphertext.len() - 1,
    ] {
        let mut changed = ciphertext.clone();
        changed[offset] ^= 1;
        assert!(open_test_request(&receiver, &changed).is_err());
    }
    assert!(open_test_request(&receiver, &ciphertext[..OVERHEAD - 1]).is_err());

    let fresh = response_secret().unwrap();
    let ciphertext = seal(&fresh.public_key(), b"plaintext").unwrap();
    assert_eq!(&*open(&fresh, &ciphertext).unwrap(), b"plaintext");
}

pub(in crate::nitro_decryption) fn open_test_request(
    receiver: &p256::SecretKey,
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NitroDecryptionError> {
    let sender = frame_sender(frame)?;
    let shared = p256::ecdh::diffie_hellman(receiver.to_nonzero_scalar(), sender.as_affine());
    open_with(
        &sender,
        &receiver.public_key(),
        shared.raw_secret_bytes(),
        frame,
    )
}
