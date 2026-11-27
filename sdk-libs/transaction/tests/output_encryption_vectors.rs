use borsh::BorshDeserialize;
use serde::Deserialize;
use spr_event::OutputDataEncoding;
use spr_keypair::{x25519::X25519_PUBKEY_LEN, EncryptionMode, ViewingKey};
use spr_transaction::{
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        poseidon_kdf::PoseidonKdf,
    },
    Data, DataRecord, DecodeCx, TransactionError, UtxoSerialization,
};

#[derive(Deserialize)]
struct Fixture {
    version: u8,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    mode: String,
    tx_secret: String,
    recipient_secret: String,
    tx_pubkey: String,
    recipient_pubkey: String,
    salt: String,
    slot_index: u32,
    asset_id: String,
    amount: String,
    blinding: String,
    memo: String,
    plaintext: String,
    ciphertext: String,
    frame: String,
}

fn fixed<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded).unwrap().try_into().unwrap()
}

#[test]
fn output_encryption_matches_shared_typescript_vectors() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../test-vectors/output_encryption.json")).unwrap();
    assert_eq!(fixture.version, 1);
    for vector in fixture.vectors {
        let mode = match vector.mode.as_str() {
            "hkdf" => EncryptionMode::Hkdf,
            "poseidonKdf" => EncryptionMode::PoseidonKdf,
            _ => panic!("unknown fixture mode"),
        };
        let tx = ViewingKey::from_bytes(&fixed(&vector.tx_secret));
        let recipient = ViewingKey::from_bytes(&fixed(&vector.recipient_secret));
        let salt = fixed(&vector.salt);
        assert_eq!(
            (
                hex::encode(tx.pubkey().as_bytes()),
                hex::encode(recipient.pubkey().as_bytes())
            ),
            (vector.tx_pubkey, vector.recipient_pubkey),
            "{} keys",
            vector.name,
        );
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: vector.asset_id.parse().unwrap(),
            amount: vector.amount.parse().unwrap(),
            blinding: fixed(&vector.blinding),
            ring_program_id: None,
            data: Data::new(vec![DataRecord::Memo(hex::decode(&vector.memo).unwrap())]),
        };
        let serialized = plaintext.serialize().unwrap();
        let ciphertext = tx
            .encrypt_slot_with_mode(
                &recipient.pubkey(),
                &serialized,
                salt,
                vector.slot_index,
                mode,
            )
            .unwrap();
        assert_eq!(
            (hex::encode(&serialized), hex::encode(&ciphertext)),
            (vector.plaintext, vector.ciphertext),
            "{} encryption",
            vector.name,
        );
        let cx = ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: recipient.pubkey(),
            salt,
            slot_index: vector.slot_index,
        };
        let encoded = match mode {
            EncryptionMode::Hkdf => Confidential::encode_plaintext(&plaintext, [0; 32], &cx),
            EncryptionMode::PoseidonKdf => PoseidonKdf::encode_plaintext(&plaintext, [0; 32], &cx),
        }
        .unwrap();
        assert_eq!(
            hex::encode(&encoded.data),
            vector.frame,
            "{} frame",
            vector.name
        );
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(&encoded.data).unwrap()
        else {
            panic!("ordinary output must use Encrypted framing");
        };
        let (&scheme, body) = blob.split_first().unwrap();
        assert_eq!(
            scheme,
            match mode {
                EncryptionMode::Hkdf => 3,
                EncryptionMode::PoseidonKdf => 9,
            }
        );
        let decode = DecodeCx {
            viewing_key: &recipient,
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(salt),
            slot_index: vector.slot_index,
            first_nullifier: None,
        };
        let (opened, sender_opened) = match mode {
            EncryptionMode::Hkdf => (
                Confidential::decode(body, &decode),
                Confidential::decrypt_with_tx_key(&tx, body, salt, vector.slot_index),
            ),
            EncryptionMode::PoseidonKdf => (
                PoseidonKdf::decode(body, &decode),
                PoseidonKdf::decrypt_with_tx_key(&tx, body, salt, vector.slot_index),
            ),
        };
        assert_eq!(
            (opened.unwrap(), sender_opened.unwrap()),
            (plaintext.clone(), plaintext),
            "{} decryption",
            vector.name
        );
        if mode == EncryptionMode::PoseidonKdf {
            let mut changed = body.to_vec();
            changed
                .get_mut(..X25519_PUBKEY_LEN)
                .unwrap()
                .copy_from_slice(ViewingKey::from_bytes(&[11; 32]).pubkey().as_bytes());
            assert_eq!(
                PoseidonKdf::decode(&changed, &decode),
                Err(TransactionError::RecipientViewingKeyMismatch)
            );
        }
    }
}
