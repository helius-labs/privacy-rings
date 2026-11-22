use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use p256::{
    ecdsa::{signature::hazmat::PrehashSigner, signature::Signer as _, SigningKey},
    SecretKey,
};
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_keypair::{NullifierKey, X25519Pubkey};

use super::{
    super::{crypto, NitroDecryptionService, Session},
    tests::fixture_replica,
    *,
};
use crate::nitro_policy::{
    accept_published_nitro_policy, now_ms, NitroCheckpointStore, NitroPolicyError,
    UnixNitroCheckpointStore,
};

const POLICY_FIXTURE: &str = include_str!("fixtures/nitro-policy.json");
const EXCHANGE_FIXTURE: &str = include_str!("fixtures/nitro-exchange.json");

fn canonical(value: &Value) -> Vec<u8> {
    let mut value = value.clone();
    value.sort_all_objects();
    json(&value).unwrap()
}

fn sign_policy(entry: &mut Value) {
    let policy = canonical(&entry["policy"]);
    for (list, domain, secrets) in [
        (
            "signatures",
            b"SPR/native-nitro/release-policy/v1".as_slice(),
            [1, 2],
        ),
        (
            "custodySignatures",
            b"SPR/native-nitro/custody-release-policy/v1".as_slice(),
            [4, 5],
        ),
    ] {
        let endorsements = entry[list].as_array_mut().unwrap();
        for (endorsement, secret) in endorsements.iter_mut().zip(secrets) {
            let mut key = [0; 32];
            key[31] = secret;
            let key = SigningKey::from_slice(&key).unwrap();
            let signature: Signature = key.sign_prehash(&digest(&[domain, &policy])).unwrap();
            endorsement["signature"] = json!(hex::encode(signature.normalize_s().to_bytes()));
        }
    }
}

fn read_http(stream: &TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream);
    let mut header = String::new();
    reader.read_line(&mut header).unwrap();
    assert_eq!(header, "POST /nitro/v1/operations HTTP/1.1\r\n");
    let mut size = None;
    loop {
        header.clear();
        assert!(reader.read_line(&mut header).unwrap() > 0);
        if header == "\r\n" {
            break;
        }
        let (name, value) = header.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("content-length") {
            size = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; size.unwrap()];
    reader.read_exact(&mut body).unwrap();
    body
}

fn reply_for(body: &[u8], owner: Pubkey, result: Value) -> Value {
    let envelope: Value = serde_json::from_slice(body).unwrap();
    let request = lower_hex(envelope["ciphertext"].as_str().unwrap()).unwrap();
    let server_secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let request = crypto::tests::open_test_request(&server_secret, &request).unwrap();
    let mut request: Value = serde_json::from_slice(&request).unwrap();
    let operation = &mut request["operation"];
    let kind = if operation["type"] == "Decrypt" {
        assert_eq!(operation["signer"], owner.to_string());
        let signature = operation
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        let key = owner_key(owner).unwrap();
        let request_digest = digest(&[
            b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1\0",
            &canonical(&request),
        ]);
        let message = owner_message(&key, NitroNetwork::Devnet, &request_digest);
        verify_owner(&key, &message, &fixed(signature.as_str().unwrap()).unwrap()).unwrap();
        Kind::ServiceDecrypt
    } else {
        assert_eq!(operation["type"], "PublicKeys");
        assert_eq!(operation["address"], owner.to_string());
        Kind::ServicePublicKeys
    };

    let key =
        parse_point(&lower_hex(request["client_response_public_key"].as_str().unwrap()).unwrap())
            .unwrap();
    let ciphertext = crypto::seal(&key, &json(&result).unwrap()).unwrap();
    let request_digest = digest(&[
        b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1\0",
        &canonical(&request),
    ]);
    let payload = json(&ProofPayload {
        operation: kind,
        request_digest: hex::encode(request_digest),
        request_id: request["request_id"].as_str().unwrap(),
        result_digest: hex::encode(digest(&[b"SPR_TVC_RESULT_V1\0", &ciphertext])),
        r#type: APP_TYPE,
        version: VERSION,
    })
    .unwrap();
    let signing = SigningKey::from_slice(&[14; 32]).unwrap();
    let signature: Signature = signing.sign(&payload);
    let fixture: Value = serde_json::from_str(EXCHANGE_FIXTURE).unwrap();
    json!({
        "version": VERSION, "request_id": request["request_id"],
        "encrypted_result": hex::encode(ciphertext), "tvc_app_proof": {
            "public_key": fixture["reply"]["tvc_app_proof"]["public_key"],
            "proof_payload": std::str::from_utf8(&payload).unwrap(),
            "signature": hex::encode(signature.normalize_s().to_bytes()), "scheme": APP_SCHEME,
        }
    })
}

struct PaymentRpc([u8; 32]);

impl crate::Rpc for PaymentRpc {
    fn get_account(
        &self,
        _: Pubkey,
    ) -> Result<Option<solana_account::Account>, crate::ClientError> {
        Ok(None)
    }

    fn genesis_hash(&self) -> Result<[u8; 32], crate::ClientError> {
        Ok(self.0)
    }
}

#[async_trait::async_trait]
impl crate::AsyncRpc for PaymentRpc {
    async fn get_account(
        &self,
        _: Pubkey,
    ) -> Result<Option<solana_account::Account>, crate::ClientError> {
        Ok(None)
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], crate::ClientError> {
        Ok(self.0)
    }
}

#[tokio::test]
async fn recovered_wallet_can_decrypt_until_its_policy_is_revoked() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let now = now_ms().unwrap();
    let mut active = fixture["envelopes"]["genesis"].clone();
    active["policy"]["validFromMs"] = json!((now - 1000).to_string());
    active["policy"]["expiresAtMs"] = json!((now + 60_000).to_string());
    active["policy"]["targets"][0]["endpoint"] = json!(&endpoint);
    sign_policy(&mut active);
    let mut pins = fixture["trust"].clone();
    pins["minimumPolicyDigest"] = json!(hex::encode(digest(&[
        b"SPR/native-nitro/release-policy/v1",
        &canonical(&active["policy"])
    ])));
    let trust = Arc::new(NitroTrust::from_json(&json(&pins).unwrap()).unwrap());
    let service = NitroDecryptionService::new(trust.clone(), store.clone()).unwrap();
    let active = json(&active).unwrap();
    let policy =
        Arc::new(accept_published_nitro_policy(&trust, [&active; 2], &*store, now).unwrap());
    let mut revocation = fixture["envelopes"]["genesis"].clone();
    revocation["policy"]["sequence"] = json!("2");
    revocation["policy"]["previousPolicyDigest"] = json!(hex::encode(policy.checkpoint().digest));
    revocation["policy"]["action"] = json!("revoke");
    revocation["policy"]["targets"] = json!([]);
    revocation["policy"]["validFromMs"] = json!((now - 1000).to_string());
    revocation["policy"]["expiresAtMs"] = json!((now + 60_000).to_string());
    sign_policy(&mut revocation);
    let revocation = json(&revocation).unwrap();

    // The transport fixture starts after attestation. The Nitro verifier tests
    // authenticate a separate fixture captured from a real AWS enclave.
    let fixture: Value = serde_json::from_str(EXCHANGE_FIXTURE).unwrap();
    service.0.cache.lock().await.session = Some(Arc::new(Session {
        policy,
        replica: fixture_replica(&fixture),
        endpoint: endpoint.parse().unwrap(),
        expires_at_ms: now + 60_000,
    }));

    let signer = Arc::new(Keypair::new_from_array([21; 32]));
    let owner = signer.pubkey();
    let viewing = X25519Pubkey::from_u([9; 32]).unwrap();
    let nullifier = NullifierKey::from_secret([0x44; 31]);
    let owner_response = json!({
        "type":"PublicKeys",
        "viewing_public_key": hex::encode(viewing.as_bytes()),
        "nullifier_public_key": hex::encode(nullifier.pubkey().unwrap()),
    });
    let boot_response =
        json!({"type":"Decrypt", "nullifier_secret":"44".repeat(31), "plaintexts":[]});
    let note_response =
        json!({"type":"Decrypt", "nullifier_secret":"44".repeat(31), "plaintexts":["abcdef"]});
    let server = tokio::spawn(async move {
        for (i, result) in [
            owner_response.clone(),
            owner_response,
            boot_response,
            note_response.clone(),
            note_response,
        ]
        .into_iter()
        .enumerate()
        {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(4), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut socket = socket.into_std().unwrap();
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(4)))
                .unwrap();
            let store = store.clone();
            let trust = trust.clone();
            let revocation = revocation.clone();
            tokio::task::spawn_blocking(move || {
                let body = read_http(&socket);
                assert!(!body
                    .windows(owner.to_string().len())
                    .any(|w| w == owner.to_string().as_bytes()));
                let reply = json(&reply_for(&body, owner, result)).unwrap();
                if i == 4 {
                    assert!(matches!(
                        accept_published_nitro_policy(
                            &trust,
                            [&revocation; 2],
                            &*store,
                            now_ms().unwrap()
                        ),
                        Err(NitroPolicyError::Revoked)
                    ));
                    assert_eq!(store.current(&trust).unwrap().unwrap().sequence, 2);
                }
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .unwrap();
                socket.write_all(&reply).unwrap();
            })
            .await
            .unwrap();
        }
    });

    let mainnet = PaymentRpc(
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
            .parse::<solana_hash::Hash>()
            .unwrap()
            .to_bytes(),
    );
    for rejected in [
        service.resolve_recipient_sync(&mainnet, owner),
        service.resolve_recipient(&mainnet, owner).await,
    ] {
        assert!(matches!(
            rejected,
            Err(crate::ClientError::NitroDecryption(
                NitroDecryptionError::NetworkMismatch
            ))
        ));
    }
    let devnet = PaymentRpc(
        "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
            .parse::<solana_hash::Hash>()
            .unwrap()
            .to_bytes(),
    );
    let address = service.resolve_recipient(&devnet, owner).await.unwrap();
    assert_eq!(address.viewing_pubkey, viewing);
    let keys = service.open(signer).await.unwrap();
    let request = DecryptRequest {
        ciphertext: &[1, 2, 3],
        viewing_pubkey: viewing,
        tx_viewing_pubkey: viewing,
        salt: [0x55; 16],
        slot_index: 11,
        label: DecryptLabel::Utxo,
    };
    let foreign = DecryptRequest {
        viewing_pubkey: X25519Pubkey::from_u([7; 32]).unwrap(),
        ..request
    };
    assert!(keys.decrypt_async(&[foreign]).await.is_err());
    let oversized = vec![0; MAX_CIPHERTEXT / 4 + 1];
    assert!(matches!(
        keys.decrypt_async(&[DecryptRequest {
            ciphertext: &oversized,
            ..request
        }])
        .await,
        Err(NitroDecryptionError::RequestTooLarge)
    ));
    assert_eq!(
        keys.decrypt_async(&[request]).await.unwrap(),
        [vec![0xab, 0xcd, 0xef]]
    );
    assert!(matches!(
        keys.decrypt_async(&[request]).await,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Rollback))
    ));
    server.await.unwrap();
}
