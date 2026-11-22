use std::{
    fs,
    os::unix::fs::{symlink, FileTypeExt},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use serde_json::{json, Value};

use super::*;

const FIXTURE: &str = include_str!("fixtures/nitro-policy.json");

struct Fixture(Value);

impl Fixture {
    fn load() -> Self {
        Self(serde_json::from_str(FIXTURE).unwrap())
    }

    fn trust(&self) -> NitroTrust {
        NitroTrust::from_json(&serde_json::to_vec(&self.0["trust"]).unwrap()).unwrap()
    }

    fn now(&self) -> u64 {
        self.0["now"].as_u64().unwrap()
    }

    fn head(&self, name: &str) -> Vec<u8> {
        let envelope = &self.0["envelopes"][name];
        assert!(envelope.is_object(), "unknown policy fixture {name}");
        serde_json::to_vec(envelope).unwrap()
    }

    fn accept(
        &self,
        trust: &NitroTrust,
        store: &dyn NitroCheckpointStore,
        primary: &str,
        mirror: &str,
    ) -> Result<AcceptedNitroPolicy, NitroPolicyError> {
        accept_published_nitro_policy(
            trust,
            [&self.head(primary), &self.head(mirror)],
            store,
            self.now(),
        )
    }
}

#[test]
fn both_published_heads_authorize_exact_target() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let policy = fixture
        .accept(&trust, &store, "genesis", "genesis")
        .unwrap();
    assert_eq!(
        hex::encode(policy.checkpoint().digest),
        fixture.0["firstDigest"].as_str().unwrap()
    );
    assert_eq!(policy.checkpoint().sequence, 1);
    assert_eq!(
        store.current(&trust).unwrap().as_ref(),
        Some(policy.checkpoint())
    );
    let [target] = policy.targets() else {
        panic!("expected one target")
    };
    assert_eq!(
        target.endpoint.as_str(),
        "https://replica.example.com/nitro/"
    );
    assert_eq!(target.release_id, "first-release");
    assert_eq!(target.executable_sha256, [0xd4; 32]);
    assert_eq!(target.custody_epoch, 1);
    assert_eq!(target.custody_digest, [0xc3; 32]);
    assert_eq!(target.pcrs[4], [0x55; 48]);
    let [(primary, first_owner), (mirror, second_owner)] = trust.publication_routes();
    let domain = "a1".repeat(32);
    assert_eq!(primary.as_str(), format!("https://fixture-release-primary.s3.us-east-1.amazonaws.com/spr-release/devnet/{domain}/policy.json"));
    assert_eq!(mirror.as_str(), format!("https://fixture-release-mirror.s3.eu-north-1.amazonaws.com/spr-release/devnet/{domain}/policy.json"));
    assert_eq!(
        (first_owner, second_owner),
        ("111111111111", "222222222222")
    );
}

#[test]
fn signed_policies_require_the_pinned_publication_pair() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let original = &fixture.0["trust"];
    let mut reversed = original.clone();
    reversed["publications"].as_array_mut().unwrap().swap(0, 1);
    let mut alternatives = vec![reversed];
    for (field, value) in [
        ("bucket", "replacement-primary"),
        ("region", "us-west-2"),
        ("account", "333333333333"),
    ] {
        let mut pins = original.clone();
        pins["publications"][0][field] = json!(value);
        alternatives.push(pins);
    }
    for pins in alternatives {
        let trust = NitroTrust::from_json(&serde_json::to_vec(&pins).unwrap()).unwrap();
        for name in ["genesis", "revoke"] {
            assert!(matches!(
                fixture.accept(&trust, &store, name, name),
                Err(NitroPolicyError::Invalid)
            ));
            assert_eq!(store.current(&trust).unwrap(), None);
        }
    }
}

#[test]
fn only_the_exact_predecessor_can_be_used_during_publication() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    for (primary, mirror) in [
        ("genesis", "successor"),
        ("skipped", "genesis"),
        ("fork", "genesis"),
        ("mutatedEpoch", "genesis"),
        ("resumed", "successor"),
        ("reducedFloor", "successor"),
    ] {
        assert!(
            matches!(
                fixture.accept(&trust, &store, primary, mirror),
                Err(NitroPolicyError::Invalid)
            ),
            "{primary}/{mirror}"
        );
        assert_eq!(store.current(&trust).unwrap(), None);
    }
    let policy = fixture
        .accept(&trust, &store, "successor", "genesis")
        .unwrap();
    assert_eq!(policy.checkpoint().sequence, 2);
    assert_eq!(policy.checkpoint().minimum_custody_epoch, 2);
    assert!(policy.checkpoint().recovery_only);
    assert_eq!(policy.targets()[0].custody_digest, [0xe5; 32]);
}

#[test]
fn both_quorums_and_strict_wire_format_are_required() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    for head in ["duplicateSigner", "onlyOneCustodian", "unpinnedSigner"] {
        for (primary, mirror) in [(head, "genesis"), ("genesis", head)] {
            assert!(
                matches!(
                    fixture.accept(&trust, &store, primary, mirror),
                    Err(NitroPolicyError::Invalid)
                ),
                "{primary}/{mirror}"
            );
        }
    }
    let genesis = fixture.head("genesis");
    let original = std::str::from_utf8(&genesis).unwrap();
    let duplicate = original.replace(
        "\"previousPolicyDigest\":null",
        "\"previousPolicyDigest\":null,\"previousPolicyDigest\":null",
    );
    let missing = original.replace("\"previousPolicyDigest\":null,", "");
    let mut without_publications = fixture.0["envelopes"]["genesis"].clone();
    without_publications["policy"]
        .as_object_mut()
        .unwrap()
        .remove("publications");
    let without_publications = serde_json::to_vec(&without_publications).unwrap();
    let tampered = original.replace("first-release", "forged-release");
    let oversized = vec![b' '; MAX_POLICY_BYTES + 1];
    for head in [
        duplicate.as_bytes(),
        missing.as_bytes(),
        &without_publications,
        tampered.as_bytes(),
        &oversized,
        b"",
    ] {
        assert!(matches!(
            accept_published_nitro_policy(&trust, [&genesis, head], &store, fixture.now()),
            Err(NitroPolicyError::Invalid)
        ));
    }
    assert_eq!(store.current(&trust).unwrap(), None);
}

#[test]
fn expiration_and_updated_trust_prevent_cached_use() {
    let mut fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let genesis = fixture.head("genesis");
    let now = fixture.now();
    for invalid_time in [now - 1001, now + 1000] {
        assert!(matches!(
            accept_published_nitro_policy(&trust, [&genesis; 2], &store, invalid_time),
            Err(NitroPolicyError::Invalid)
        ));
    }
    assert_eq!(store.current(&trust).unwrap(), None);
    let policy = fixture
        .accept(&trust, &store, "genesis", "genesis")
        .unwrap();
    policy.require_current(&trust, &store, now).unwrap();
    assert!(matches!(
        policy.require_current(&trust, &store, now + 1000),
        Err(NitroPolicyError::Invalid)
    ));

    fixture.0["trust"]["minimumSequence"] = json!("2");
    fixture.0["trust"]["minimumPolicyDigest"] =
        fixture.0["envelopes"]["revoke"]["policy"]["previousPolicyDigest"].clone();
    fixture.0["trust"]["minimumCustodyEpoch"] = json!("2");
    let updated = fixture.trust();
    assert!(matches!(
        policy.require_current(&updated, &store, now),
        Err(NitroPolicyError::Invalid)
    ));
    assert!(matches!(
        fixture.accept(&updated, &store, "genesis", "genesis"),
        Err(NitroPolicyError::Invalid)
    ));
    fixture
        .accept(&updated, &store, "successor", "genesis")
        .unwrap();
}

#[test]
fn checkpoint_read_cannot_extend_the_policy_deadline() {
    struct ReadAdvancesTime<'a> {
        clock: &'a AtomicU64,
        deadline: u64,
        checkpoint: NitroCheckpoint,
    }
    impl NitroCheckpointStore for ReadAdvancesTime<'_> {
        fn current(&self, _: &NitroTrust) -> Result<Option<NitroCheckpoint>, NitroPolicyError> {
            self.clock.store(self.deadline, Ordering::Relaxed);
            Ok(Some(self.checkpoint.clone()))
        }

        fn accept(
            &self,
            _: &NitroTrust,
            _: &NitroPolicyUpdate<'_>,
        ) -> Result<bool, NitroPolicyError> {
            unreachable!("this store only reads the checkpoint")
        }
    }

    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let policy = fixture
        .accept(&trust, &store, "genesis", "genesis")
        .unwrap();
    let clock = AtomicU64::new(fixture.now());
    let reader = ReadAdvancesTime {
        clock: &clock,
        deadline: policy.expires_at_ms,
        checkpoint: policy.checkpoint().clone(),
    };
    assert!(matches!(
        policy.require_current_with_clock(&trust, &reader, || Ok(clock.load(Ordering::Relaxed))),
        Err(NitroPolicyError::Invalid)
    ));
}

#[test]
fn shipped_anchor_rejects_signed_forks_before_persisting() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    for (primary, mirror) in [
        ("competingGenesis", "competingGenesis"),
        ("fork", "fork"),
        ("fork", "genesis"),
    ] {
        assert!(matches!(
            fixture.accept(&trust, &store, primary, mirror),
            Err(NitroPolicyError::Invalid)
        ));
        assert_eq!(store.current(&trust).unwrap(), None);
    }
    fixture
        .accept(&trust, &store, "successor", "successor")
        .unwrap();
}

#[test]
fn revocation_persists_across_restart() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let prior = fixture
        .accept(&trust, &store, "successor", "genesis")
        .unwrap();
    assert!(matches!(
        fixture.accept(&trust, &store, "revoke", "successor"),
        Err(NitroPolicyError::Revoked)
    ));

    let reopened = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    assert_eq!(reopened.current(&trust).unwrap().unwrap().sequence, 3);
    assert!(matches!(
        prior.require_current(&trust, &reopened, fixture.now()),
        Err(NitroPolicyError::Superseded)
    ));
    assert!(matches!(
        fixture.accept(&trust, &reopened, "successor", "successor"),
        Err(NitroPolicyError::Rollback)
    ));
    assert!(matches!(
        fixture.accept(&trust, &reopened, "revoke", "revoke"),
        Err(NitroPolicyError::Revoked)
    ));
}

#[cfg(feature = "reqwest")]
#[test]
fn live_reader_remembers_revocation_after_checkpoint_file_is_lost_or_rolled_back() {
    use std::sync::Mutex;

    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let path = dir.path().join(format!(
        "devnet-{}.json",
        hex::encode(trust.security_domain_id())
    ));
    let accept = |primary, mirror, latest: &mut Option<NitroCheckpoint>| {
        accept_with_checkpoint(
            &trust,
            [&fixture.head(primary), &fixture.head(mirror)],
            &store,
            fixture.now(),
            latest,
        )
    };
    let mut latest = None;
    let prior = accept("successor", "genesis", &mut latest).unwrap();
    let backup = fs::read(&path).unwrap();
    assert!(matches!(
        accept("revoke", "successor", &mut latest),
        Err(NitroPolicyError::Revoked)
    ));
    let remembered = latest.clone().unwrap();
    assert_eq!(remembered.sequence, 3);

    fs::remove_file(&path).unwrap();
    assert!(matches!(
        accept("successor", "successor", &mut latest),
        Err(NitroPolicyError::Rollback)
    ));
    assert_eq!(store.current(&trust).unwrap(), None);

    fs::write(&path, backup).unwrap();
    assert!(prior.require_current(&trust, &store, fixture.now()).is_ok());
    assert!(matches!(
        publication::require_current(&prior, &trust, &store, &Mutex::new(latest.clone()), || Ok(
            fixture.now()
        )),
        Err(NitroPolicyError::Superseded)
    ));
    assert!(matches!(
        accept("successor", "successor", &mut latest),
        Err(NitroPolicyError::Rollback)
    ));
    assert!(matches!(
        accept("revoke", "revoke", &mut latest),
        Err(NitroPolicyError::Revoked)
    ));
    assert_eq!(store.current(&trust).unwrap(), Some(remembered));
}

#[test]
fn concurrent_clients_cannot_restore_or_replace_a_checkpoint() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let other = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    thread::scope(|scope| {
        let old = scope.spawn(|| fixture.accept(&trust, &store, "genesis", "genesis"));
        let new = scope.spawn(|| fixture.accept(&trust, &other, "successor", "genesis"));
        let prior = old.join().unwrap();
        new.join().unwrap().unwrap();
        if let Ok(prior) = prior {
            assert!(matches!(
                prior.require_current(&trust, &store, fixture.now()),
                Err(NitroPolicyError::Superseded)
            ));
        } else {
            assert!(matches!(
                prior,
                Err(NitroPolicyError::Rollback | NitroPolicyError::Superseded)
            ));
        }
    });
    let current = store.current(&trust).unwrap().unwrap();
    assert_eq!(current.sequence, 2);
    assert!(matches!(
        fixture.accept(&trust, &other, "competingSuccessor", "competingSuccessor"),
        Err(NitroPolicyError::Rollback),
    ));
    assert_eq!(store.current(&trust).unwrap(), Some(current));
}

#[test]
fn rejects_nonregular_checkpoint_and_lock_files_without_waiting() {
    for extension in ["json", "lock"] {
        for is_symlink in [false, true] {
            let fixture = Fixture::load();
            let trust = fixture.trust();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!(
                "devnet-{}.{extension}",
                hex::encode(trust.security_domain_id())
            ));
            if is_symlink {
                symlink(directory.path().join("missing"), &path).unwrap();
            } else {
                assert!(Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success());
            }
            let store = UnixNitroCheckpointStore::open(directory.path()).unwrap();
            let (finished, result) = mpsc::channel();
            thread::spawn(move || {
                let accepted = fixture.accept(&trust, &store, "genesis", "genesis");
                let _ = finished.send(accepted.map(|_| ()));
            });
            assert!(matches!(
                result.recv_timeout(Duration::from_secs(3)).unwrap(),
                Err(NitroPolicyError::Storage)
            ));
            let file_type = fs::symlink_metadata(&path).unwrap().file_type();
            assert_eq!(file_type.is_symlink(), is_symlink);
            assert_eq!(file_type.is_fifo(), !is_symlink);
        }
    }
}

#[test]
fn stalled_checkpoint_lock_fails_closed_and_leaves_the_revision_intact() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let directory = tempfile::tempdir().unwrap();
    let store = UnixNitroCheckpointStore::open(directory.path()).unwrap();
    let genesis = fixture
        .accept(&trust, &store, "genesis", "genesis")
        .unwrap();
    let lock_path = directory.path().join(format!(
        "devnet-{}.lock",
        hex::encode(trust.security_domain_id())
    ));
    let lock = fs::OpenOptions::new().write(true).open(lock_path).unwrap();
    lock.lock().unwrap();
    thread::scope(|scope| {
        let (finished, results) = mpsc::channel();
        let read = finished.clone();
        let store = &store;
        let trust = &trust;
        let fixture = &fixture;
        scope.spawn(move || read.send(store.current(trust).map(|_| ())));
        scope.spawn(move || {
            finished.send(
                fixture
                    .accept(trust, store, "successor", "genesis")
                    .map(|_| ()),
            )
        });
        let first = results.recv_timeout(Duration::from_secs(5));
        let second = results.recv_timeout(Duration::from_secs(5));
        drop(lock);
        assert!(matches!(first, Ok(Err(NitroPolicyError::Storage))));
        assert!(matches!(second, Ok(Err(NitroPolicyError::Storage))));
    });
    assert_eq!(
        store.current(&trust).unwrap().as_ref(),
        Some(genesis.checkpoint())
    );
    assert_eq!(
        fixture
            .accept(&trust, &store, "successor", "genesis")
            .unwrap()
            .checkpoint()
            .sequence,
        2
    );
}

#[test]
fn restored_checkpoint_rejects_a_disputed_predecessor_from_either_feed() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let writer = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    let saved = fixture
        .accept(&trust, &writer, "successor", "genesis")
        .unwrap();
    let restored = UnixNitroCheckpointStore::open(dir.path()).unwrap();
    for (primary, mirror) in [
        ("forkOfAccepted", "forkOfAccepted"),
        ("forkOfAccepted", "competingSuccessor"),
        ("witnessedFork", "forkOfAccepted"),
    ] {
        assert!(matches!(
            fixture.accept(&trust, &restored, primary, mirror),
            Err(NitroPolicyError::Rollback)
        ));
        assert_eq!(
            restored.current(&trust).unwrap().as_ref(),
            Some(saved.checkpoint())
        );
    }
    assert!(matches!(
        fixture.accept(&trust, &restored, "agreedCatchUp", "agreedCatchUp"),
        Err(NitroPolicyError::Revoked)
    ));
    assert_eq!(restored.current(&trust).unwrap().unwrap().sequence, 4);
}

#[test]
fn missing_store_or_corrupt_checkpoint_never_authorizes_a_replica() {
    let fixture = Fixture::load();
    let trust = fixture.trust();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoints");
    fs::create_dir(&path).unwrap();
    let store = UnixNitroCheckpointStore::open(&path).unwrap();
    fs::remove_dir(&path).unwrap();
    assert!(matches!(
        fixture.accept(&trust, &store, "genesis", "genesis"),
        Err(NitroPolicyError::Storage)
    ));

    fs::create_dir(&path).unwrap();
    let filename = format!("devnet-{}.json", hex::encode(trust.security_domain_id()));
    fs::write(path.join(filename), b"corrupt").unwrap();
    assert!(matches!(
        fixture.accept(&trust, &store, "genesis", "genesis"),
        Err(NitroPolicyError::Storage)
    ));
}

#[test]
fn trust_requires_independent_publications_and_nonoverlapping_authorities() {
    let fixture = Fixture::load();
    let original = &fixture.0["trust"];
    let mut repeated_account = original.clone();
    repeated_account["publications"][1]["account"] = original["publications"][0]["account"].clone();
    let mut repeated_bucket = original.clone();
    repeated_bucket["publications"][1]["bucket"] = original["publications"][0]["bucket"].clone();
    let mut overlapping_keys = original.clone();
    overlapping_keys["custodyKeys"][0] = original["keys"][0].clone();
    for trust in [repeated_account, repeated_bucket, overlapping_keys] {
        assert!(matches!(
            NitroTrust::from_json(&serde_json::to_vec(&trust).unwrap()),
            Err(NitroPolicyError::Trust)
        ));
    }
}
