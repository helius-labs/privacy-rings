use p256::PublicKey as P256Key;
use serde_json::{json, Value};
use spr_keypair::X25519Pubkey;

use super::*;

const FIXTURE: &str = include_str!("fixtures/nitro-exchange.json");

fn request<'a>(fixture: &Value, info: &'a Info, operation: Operation) -> Request<'a> {
    let response_key = fixture["decrypt"]["client_response_public_key"]
        .as_str()
        .unwrap();
    Request::new(
        info,
        &[3; 32],
        &parse_point(&lower_hex(response_key).unwrap()).unwrap(),
        operation,
    )
}

fn decrypt_operation(owner: Pubkey) -> Operation {
    let viewing_key = X25519Pubkey::from_u([7; 32]).unwrap();
    Operation::decrypt(
        owner,
        &[DecryptRequest {
            ciphertext: &[0x88, 0, 0x22],
            salt: [0x55; 16],
            slot_index: 11,
            label: DecryptLabel::Utxo,
            tx_viewing_pubkey: viewing_key,
            viewing_pubkey: X25519Pubkey::from_u([9; 32]).unwrap(),
        }],
    )
}

pub(super) fn fixture_replica(fixture: &Value) -> Replica {
    let proof_public = fixture["reply"]["tvc_app_proof"]["public_key"]
        .as_str()
        .unwrap();
    let info: Info = serde_json::from_value(fixture["info"].clone()).unwrap();
    let encryption = lower_hex(&info.quorum_public_key).unwrap();
    let proof = lower_hex(proof_public).unwrap();
    Replica {
        info,
        encryption: P256Key::from_sec1_bytes(&encryption[..POINT_BYTES]).unwrap(),
        proof_key: VerifyingKey::from_sec1_bytes(&proof[POINT_BYTES..]).unwrap(),
        proof_public: proof_public.to_owned(),
        valid_from_ms: 0,
        valid_through_ms: u64::MAX,
    }
}

#[test]
fn canonical_discovery_binds_exact_typed_fields() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let boot: Boot = serde_json::from_value(fixture["boot"].clone()).unwrap();
    assert_eq!(hex::encode(boot.binding().unwrap()), fixture["bootDigest"]);
    let forged = json!({"boot": fixture["boot"], "evidence": "00"});
    let trust_fixture: Value =
        serde_json::from_str(include_str!("fixtures/nitro-policy.json")).unwrap();
    let trust =
        NitroTrust::from_json(&serde_json::to_vec(&trust_fixture["trust"]).unwrap()).unwrap();
    let target = NitroTarget {
        endpoint: url::Url::parse("https://example.com").unwrap(),
        release_id: "first-release".into(),
        executable_sha256: [0xd4; 32],
        custody_epoch: 1,
        custody_digest: [0xc3; 32],
        pcrs: [[1; 48]; 5],
    };
    let attestation: Attestation = serde_json::from_value(forged.clone()).unwrap();
    assert!(attestation
        .verify(&trust, &target, &[7; 32], 1795290720000)
        .is_err());
    let mut new_release = forged;
    new_release["boot"]["info"]["release_id"] = json!("other");
    let attestation: Attestation = serde_json::from_value(new_release).unwrap();
    assert!(attestation
        .verify(&trust, &target, &[7; 32], 1795290720000)
        .is_err());
}

#[test]
fn signs_the_same_request_and_owner_message_as_the_service_sdk() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let replica = fixture_replica(&fixture);
    let owner = Pubkey::new_from_array(fixed(fixture["ownerBytes"].as_str().unwrap()).unwrap());
    let keys = request(&fixture, &replica.info, Operation::public_keys(owner));
    assert_eq!(
        hex::encode(keys.unsigned_digest().unwrap()),
        fixture["publicDigest"]
    );
    assert_eq!(serde_json::to_value(&keys).unwrap(), fixture["publicKeys"]);

    let mut decrypt = request(&fixture, &replica.info, decrypt_operation(owner));
    let digest = decrypt.unsigned_digest().unwrap();
    assert_eq!(hex::encode(digest), fixture["decryptDigest"]);
    let key = owner_key(owner).unwrap();
    let message = owner_message(&key, NitroNetwork::Devnet, &digest);
    assert_eq!(hex::encode(&message), fixture["ownerMessage"]);
    let signature = fixed(
        fixture["decrypt"]["operation"]["signature"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    verify_owner(&key, &message, &signature).unwrap();
    assert!(verify_owner(
        &key,
        &owner_message(&key, NitroNetwork::Mainnet, &digest),
        &signature
    )
    .is_err());
    assert!(owner_key(Pubkey::default()).is_err());
    decrypt.set_signature(&signature);
    assert_eq!(serde_json::to_value(&decrypt).unwrap(), fixture["decrypt"]);
}

#[test]
fn response_authenticates_this_boot_request_and_ciphertext() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let replica = fixture_replica(&fixture);
    let owner = Pubkey::new_from_array(fixed(fixture["ownerBytes"].as_str().unwrap()).unwrap());
    let request = request(&fixture, &replica.info, decrypt_operation(owner));
    let digest = request.unsigned_digest().unwrap();
    let reply = &fixture["reply"];
    let deserialize = |value: Value| serde_json::from_value::<EncryptedResponse>(value).unwrap();
    request
        .verify_response(&replica, deserialize(reply.clone()), &digest)
        .unwrap();
    assert!(request
        .verify_response(&replica, deserialize(reply.clone()), &[0; 32])
        .is_err());

    let alternate_boot = Replica {
        proof_public: hex::encode([0; 130]),
        ..fixture_replica(&fixture)
    };
    assert!(request
        .verify_response(&alternate_boot, deserialize(reply.clone()), &digest)
        .is_err());
    for (keys, replacement) in [
        (&["request_id"][..], "00".repeat(32)),
        (&["encrypted_result"][..], "abcdef".into()),
        (&["tvc_app_proof", "proof_payload"][..], "{}".into()),
        (&["tvc_app_proof", "signature"][..], "00".repeat(64)),
        (&["tvc_app_proof", "scheme"][..], "other-scheme".into()),
    ] {
        let mut response = reply.clone();
        let value = keys
            .iter()
            .fold(&mut response, |nested, key| &mut nested[*key]);
        *value = json!(replacement);
        assert!(request
            .verify_response(&replica, deserialize(response), &digest)
            .is_err());
    }
    let mut high_s = reply.clone();
    high_s["tvc_app_proof"]["signature"] = fixture["highSSignature"].clone();
    assert!(request
        .verify_response(&replica, deserialize(high_s), &digest)
        .is_err());
}
