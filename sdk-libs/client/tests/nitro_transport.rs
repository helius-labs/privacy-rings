use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

use p256::{
    ecdsa::{signature::hazmat::PrehashSigner, signature::Signer as _, SigningKey},
    SecretKey,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_signer::{Signer, SignerError};
use spr_keypair::{NullifierKey, X25519Pubkey};
use tokio::time::Instant;

use super::{
    super::{
        crypto, retry_public_keys, NitroDecryptionService, Session, SessionWindow, SESSION_MS,
    },
    tests::fixture_replica,
    *,
};
use crate::nitro_policy::{
    accept_published_nitro_policy, now_ms, NitroCheckpoint, NitroCheckpointStore, NitroPolicyError,
    NitroPolicyUpdate, UnixNitroCheckpointStore,
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

fn reply_for(body: &[u8], owner: Pubkey, result: Value, session_expires_at_ms: u64) -> Value {
    let envelope: Value = serde_json::from_slice(body).unwrap();
    let request = lower_hex(envelope["ciphertext"].as_str().unwrap()).unwrap();
    let server_secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let request = crypto::tests::open_test_request(&server_secret, &request).unwrap();
    let mut request: Value = serde_json::from_slice(&request).unwrap();
    let operation = &mut request["operation"];
    let kind = if operation["type"] == "Decrypt" {
        assert_eq!(operation["signer"], owner.to_string());
        let deadline = operation["expires_at_ms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!((now_ms().unwrap() + 1..=session_expires_at_ms).contains(&deadline));
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

fn accepted_boot(
    fixture: &Value,
    endpoint: &str,
    now: u64,
    store: &UnixNitroCheckpointStore,
) -> (Arc<NitroTrust>, Arc<Session>, Vec<u8>) {
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
    let active = json(&active).unwrap();
    let policy = Arc::new(accept_published_nitro_policy(&trust, [&active; 2], store, now).unwrap());
    // Transport tests start after attestation. The AWS verifier has its own evidence fixture.
    let exchange: Value = serde_json::from_str(EXCHANGE_FIXTURE).unwrap();
    let session = Arc::new(Session {
        policy,
        replica: fixture_replica(&exchange),
        endpoint: endpoint.parse().unwrap(),
        window: SessionWindow {
            expires_at_ms: now + SESSION_MS,
            deadline: Instant::now() + Duration::from_millis(SESSION_MS),
        },
    });
    (trust, session, active)
}

fn revoke(active: &[u8], session: &Session) -> Vec<u8> {
    let mut revocation: Value = serde_json::from_slice(active).unwrap();
    revocation["policy"]["sequence"] = json!("2");
    revocation["policy"]["previousPolicyDigest"] =
        json!(hex::encode(session.policy.checkpoint().digest));
    revocation["policy"]["action"] = json!("revoke");
    revocation["policy"]["targets"] = json!([]);
    sign_policy(&mut revocation);
    json(&revocation).unwrap()
}

struct PublishingSigner(Keypair, Box<dyn Fn() + Send + Sync>);

impl Signer for PublishingSigner {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.0.try_pubkey()
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<solana_signature::Signature, SignerError> {
        (self.1)();
        self.0.try_sign_message(message)
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn a_revoked_cached_boot_cannot_collect_or_send_owner_approval() {
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    for during_signing in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
        let (trust, session, active) =
            accepted_boot(&fixture, &endpoint, now_ms().unwrap(), &store);
        let revoked = revoke(&active, &session);
        let service = NitroDecryptionService::new(trust.clone(), store.clone()).unwrap();
        let initial = if during_signing {
            active
        } else {
            revoked.clone()
        };
        *service.0.policies.test_heads.lock().unwrap() = Some([initial.clone(), initial]);
        service.0.cache.lock().await.session = Some(session);
        let approvals = Arc::new(AtomicUsize::default());
        let signer = Arc::new(PublishingSigner(
            Keypair::new_from_array([21; 32]),
            Box::new({
                let service = service.clone();
                let approvals = approvals.clone();
                move || {
                    approvals.fetch_add(1, Ordering::SeqCst);
                    *service.0.policies.test_heads.lock().unwrap() =
                        Some([revoked.clone(), revoked.clone()]);
                }
            }),
        ));
        let owner = signer.pubkey();
        let result = tokio::select! {
            result = service.decrypt_batch(owner, signer, &[]) => result,
            _ = listener.accept() => panic!("sent an owner approval to the revoked boot"),
        };
        assert!(matches!(
            result,
            Err(NitroDecryptionError::Policy(NitroPolicyError::Revoked))
        ));
        assert_eq!(
            approvals.load(Ordering::SeqCst),
            usize::from(during_signing)
        );
        assert_eq!(store.current(&trust).unwrap().unwrap().sequence, 2);
    }
}

#[tokio::test]
async fn approval_deadline_cancels_a_stalled_replica_exchange() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let (trust, session, active) = accepted_boot(&fixture, &endpoint, now_ms().unwrap(), &store);
    let service = NitroDecryptionService::new(trust, store).unwrap();
    *service.0.policies.test_heads.lock().unwrap() = Some([active.clone(), active]);
    let signer = Arc::new(Keypair::new_from_array([21; 32]));
    let owner = signer.pubkey();
    let approval_ms = 2_000;
    let operation = Operation::decrypt(owner, &[], now_ms().unwrap() + approval_ms);
    let exchange = tokio::spawn(async move {
        service
            .0
            .exchange(&session, operation, Some((owner, signer)))
            .await
    });
    let (_stalled_reply, _) =
        tokio::time::timeout(Duration::from_millis(approval_ms), listener.accept())
            .await
            .unwrap()
            .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(approval_ms)).await;
    assert!(matches!(
        exchange.await.unwrap(),
        Err(NitroDecryptionError::SessionExpired)
    ));
}

#[tokio::test]
async fn a_cached_boot_cannot_resolve_payments_under_a_new_recovery_policy() {
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let now = now_ms().unwrap();
    let (trust, session, old) = accepted_boot(&fixture, "http://127.0.0.1/", now, &store);
    let service = NitroDecryptionService::new(trust.clone(), store.clone()).unwrap();
    let mut recovery: Value = serde_json::from_slice(&old).unwrap();
    recovery["policy"]["sequence"] = json!("2");
    recovery["policy"]["previousPolicyDigest"] =
        json!(hex::encode(session.policy.checkpoint().digest));
    recovery["policy"]["recoveryOnly"] = json!(true);
    sign_policy(&mut recovery);
    *service.0.policies.test_heads.lock().unwrap() = Some([json(&recovery).unwrap(), old]);
    service.0.cache.lock().await.session = Some(session.clone());
    let owner = Keypair::new_from_array([21; 32]).pubkey();

    assert!(matches!(
        service.address(owner).await,
        Err(NitroDecryptionError::RecoveryOnly)
    ));
    let checkpoint = store.current(&trust).unwrap().unwrap();
    assert_eq!(checkpoint.sequence, 2);
    assert!(checkpoint.recovery_only);
}

#[tokio::test(start_paused = true)]
async fn cached_policy_expires_by_monotonic_time_even_if_wall_time_remains_valid() {
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let (trust, session, _) =
        accepted_boot(&fixture, "http://127.0.0.1/", now_ms().unwrap(), &store);
    let service = NitroDecryptionService::new(trust, store).unwrap();
    tokio::time::advance(Duration::from_millis(SESSION_MS - 1)).await;
    service.0.require_current(&session).await.unwrap();
    tokio::time::advance(Duration::from_millis(1)).await;
    session.policy.require_valid_at(now_ms().unwrap()).unwrap();
    assert!(matches!(
        service.0.require_current(&session).await,
        Err(NitroDecryptionError::SessionExpired)
    ));
}

#[tokio::test]
async fn payment_lookup_discards_valid_reply_after_revocation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let (trust, session, active) = accepted_boot(&fixture, &endpoint, now_ms().unwrap(), &store);
    let service = NitroDecryptionService::new(trust.clone(), store.clone()).unwrap();
    let revocation = revoke(&active, &session);
    *service.0.policies.test_heads.lock().unwrap() = Some([active.clone(), active]);
    service.0.cache.lock().await.session = Some(session.clone());

    let owner = Keypair::new_from_array([21; 32]).pubkey();
    let publisher = service.clone();
    let reply = async move {
        let (socket, _) = tokio::time::timeout(Duration::from_secs(4), listener.accept())
            .await
            .unwrap()
            .unwrap();
        tokio::task::spawn_blocking(move || {
            let mut socket = socket.into_std().unwrap();
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let body = read_http(&socket);
            let result = json!({
                "type": "PublicKeys",
                "viewing_public_key": hex::encode(X25519Pubkey::from_u([9; 32]).unwrap().as_bytes()),
                "nullifier_public_key": "00".repeat(32),
            });
            let response =
                json(&reply_for(&body, owner, result, session.window.expires_at_ms)).unwrap();
            *publisher.0.policies.test_heads.lock().unwrap() =
                Some([revocation.clone(), revocation]);
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            socket.write_all(&response).unwrap();
        })
        .await
        .unwrap();
    };
    let (lookup, ()) = tokio::join!(service.address(owner), reply);
    assert!(matches!(
        lookup,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Revoked))
    ));
    assert_eq!(store.current(&trust).unwrap().unwrap().sequence, 2);
}

#[tokio::test(start_paused = true)]
async fn checkpoint_wait_cannot_dispatch_a_probe_after_the_freshness_deadline() {
    struct StalledCheckpoint {
        checkpoint: NitroCheckpoint,
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl NitroCheckpointStore for StalledCheckpoint {
        fn current(&self, _: &NitroTrust) -> Result<Option<NitroCheckpoint>, NitroPolicyError> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| NitroPolicyError::Storage)?;
            }
            Ok(Some(self.checkpoint.clone()))
        }

        fn accept(
            &self,
            _: &NitroTrust,
            _: &NitroPolicyUpdate<'_>,
        ) -> Result<bool, NitroPolicyError> {
            unreachable!("attestation only reads the checkpoint")
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(directory.path()).unwrap();
    let (trust, session, _) = accepted_boot(&fixture, &endpoint, now_ms().unwrap(), &store);
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, released) = mpsc::channel();
    let store = Arc::new(StalledCheckpoint {
        checkpoint: session.policy.checkpoint().clone(),
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(released),
    });
    let service = NitroDecryptionService::new(trust, store).unwrap();
    let probe = tokio::spawn(async move {
        service
            .0
            .attest(
                session.policy.clone(),
                &session.policy.targets()[0],
                session.window,
            )
            .await
    });
    waiting.await.unwrap();
    tokio::time::advance(Duration::from_millis(SESSION_MS)).await;
    let result = probe.await.unwrap();
    release.send(()).unwrap();
    assert!(matches!(result, Err(NitroDecryptionError::SessionExpired)));
    assert!(
        tokio::time::timeout(Duration::from_millis(1), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unsigned_lookup_refreshes_one_superseded_policy_and_reports_its_result() {
    let mut outcomes = [
        Err(NitroPolicyError::Superseded.into()),
        Err::<(), _>(NitroPolicyError::Revoked.into()),
    ]
    .into_iter();
    assert!(matches!(
        retry_public_keys(async || outcomes.next().unwrap()).await,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Revoked))
    ));
    assert!(outcomes.next().is_none());

    let mut outcomes = [Err(NitroPolicyError::Rollback.into()), Ok(())].into_iter();
    assert!(matches!(
        retry_public_keys(async || outcomes.next().unwrap()).await,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Rollback))
    ));
    assert!(matches!(outcomes.next(), Some(Ok(()))));

    let mut outcomes = [Err(NitroPolicyError::Superseded.into()), Ok(42)].into_iter();
    assert_eq!(
        retry_public_keys(async || outcomes.next().unwrap())
            .await
            .unwrap(),
        42
    );
}

#[tokio::test]
async fn recovered_wallet_can_decrypt_until_its_policy_is_revoked() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let now = now_ms().unwrap();
    let (trust, session, active) = accepted_boot(&fixture, &endpoint, now, &store);
    let service = NitroDecryptionService::new(trust.clone(), store.clone()).unwrap();
    let revocation = revoke(&active, &session);
    *service.0.policies.test_heads.lock().unwrap() = Some([active.clone(), active]);

    service.0.cache.lock().await.session = Some(session.clone());

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
    let session_expires_at_ms = session.window.expires_at_ms;
    let publisher = service.clone();
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
            let publisher = publisher.clone();
            let revocation = revocation.clone();
            tokio::task::spawn_blocking(move || {
                let body = read_http(&socket);
                assert!(!body
                    .windows(owner.to_string().len())
                    .any(|w| w == owner.to_string().as_bytes()));
                let reply = json(&reply_for(&body, owner, result, session_expires_at_ms)).unwrap();
                if i == 4 {
                    *publisher.0.policies.test_heads.lock().unwrap() =
                        Some([revocation.clone(), revocation]);
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
    assert_eq!(address.address().viewing_pubkey, viewing);
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
        Err(NitroDecryptionError::Policy(NitroPolicyError::Revoked))
    ));
    assert_eq!(store.current(&trust).unwrap().unwrap().sequence, 2);
    server.await.unwrap();
    assert!(matches!(
        service
            .0
            .attest(
                session.policy.clone(),
                &session.policy.targets()[0],
                session.window
            )
            .await,
        Err(NitroDecryptionError::Policy(NitroPolicyError::Superseded))
    ));
}

#[tokio::test]
async fn completed_exchange_evicts_failed_boot_and_keeps_rate_limited_boot() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/nitro/", listener.local_addr().unwrap());
    let fixture: Value = serde_json::from_str(POLICY_FIXTURE).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap());
    let (trust, session, _) = accepted_boot(&fixture, &endpoint, now_ms().unwrap(), &store);
    let service = NitroDecryptionService::new(trust, store).unwrap();
    service.0.cache.lock().await.session = Some(session.clone());

    let statuses = [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ];
    let server = tokio::spawn(async move {
        for status in statuses {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(4), listener.accept())
                .await
                .unwrap()
                .unwrap();
            tokio::task::spawn_blocking(move || {
                let mut socket = socket.into_std().unwrap();
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                read_http(&socket);
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            })
            .await
            .unwrap();
        }
    });

    let owner = Keypair::new_from_array([21; 32]).pubkey();
    for status in statuses {
        let result = service
            .0
            .exchange(&session, Operation::public_keys(owner), None)
            .await;
        assert!(matches!(result, Err(NitroDecryptionError::Http(actual)) if actual == status));
        let cache = service.0.cache.lock().await;
        assert_eq!(
            cache.session.is_some(),
            status == StatusCode::TOO_MANY_REQUESTS
        );
    }
    server.await.unwrap();
}
