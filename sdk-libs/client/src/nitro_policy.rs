//! Authenticate the standalone decryption policy before selecting a replica.

mod checkpoint;
#[cfg(feature = "reqwest")]
mod publication;
mod wire;

use std::collections::{BTreeMap, BTreeSet};

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub use checkpoint::NitroCheckpointStore;
#[cfg(unix)]
pub use checkpoint::UnixNitroCheckpointStore;
#[cfg(feature = "reqwest")]
pub use publication::NitroPolicyReader;
#[cfg(feature = "reqwest")]
pub(crate) use publication::{now_ms, read_limited};

const MAX_POLICY_BYTES: usize = 32_768;
const MAX_AUTHORITIES: usize = 8;
const MAX_TARGETS: usize = 8;
const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const RELEASE_DOMAIN: &[u8] = b"SPR/native-nitro/release-policy/v1";
const CUSTODY_DOMAIN: &[u8] = b"SPR/native-nitro/custody-release-policy/v1";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NitroPolicyError {
    #[error("invalid standalone decryption trust pins")]
    Trust,
    #[error("standalone decryption policy is invalid")]
    Invalid,
    #[error("standalone decryption policy publication is unavailable")]
    Unavailable,
    #[error("standalone decryption policy would roll back or replace an accepted revision")]
    Rollback,
    #[error("standalone decryption checkpoint storage failed")]
    Storage,
    #[error("standalone decryption was revoked")]
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NitroNetwork {
    Devnet,
    Mainnet,
}

impl NitroNetwork {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Mainnet => "mainnet",
        }
    }
}

/// Pins distributed independently of the policy publishers and enclave.
pub struct NitroTrust {
    fingerprint: [u8; 32],
    network: NitroNetwork,
    security_domain_id: [u8; 32],
    note_seed_commitment: [u8; 32],
    minimum_custody_epoch: u64,
    minimum_sequence: u64,
    minimum_policy_digest: [u8; 32],
    recovery_only: bool,
    publications: [Publication; 2],
    threshold: usize,
    keys: Vec<[u8; 65]>,
    custody_keys: Vec<[u8; 65]>,
}

struct Publication {
    endpoint: Url,
    account: String,
}

impl NitroTrust {
    pub fn from_json(input: &[u8]) -> Result<Self, NitroPolicyError> {
        let invalid = |_| NitroPolicyError::Trust;
        let trust: wire::Trust = serde_json::from_slice(bounded(input).map_err(invalid)?)
            .map_err(|_| NitroPolicyError::Trust)?;
        if trust.publications[0].bucket == trust.publications[1].bucket
            || trust.publications[0].account == trust.publications[1].account
            || !(2..=trust.keys.len()).contains(&trust.threshold)
            || trust.keys.len() > MAX_AUTHORITIES
            || trust.custody_keys.len() != 3
        {
            return Err(NitroPolicyError::Trust);
        }
        let mut seen = BTreeSet::new();
        let mut parse_keys = |keys: Vec<String>| {
            keys.iter()
                .map(|key| {
                    let key = fixed(key)?;
                    verifier(&key)?;
                    if !seen.insert(key) {
                        return Err(NitroPolicyError::Invalid);
                    }
                    Ok(key)
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let keys = parse_keys(trust.keys).map_err(invalid)?;
        let custody_keys = parse_keys(trust.custody_keys).map_err(invalid)?;
        let [primary, mirror] = trust.publications;
        let endpoint = |p| publication(p, trust.network, &trust.security_domain_id);
        Ok(Self {
            fingerprint: Sha256::digest(input).into(),
            network: trust.network,
            security_domain_id: identifier(&trust.security_domain_id).map_err(invalid)?,
            note_seed_commitment: identifier(&trust.note_seed_commitment).map_err(invalid)?,
            minimum_custody_epoch: positive(&trust.minimum_custody_epoch).map_err(invalid)?,
            minimum_sequence: positive(&trust.minimum_sequence).map_err(invalid)?,
            minimum_policy_digest: identifier(&trust.minimum_policy_digest).map_err(invalid)?,
            recovery_only: trust.recovery_only,
            publications: [endpoint(primary)?, endpoint(mirror)?],
            threshold: trust.threshold,
            keys,
            custody_keys,
        })
    }

    pub fn network(&self) -> NitroNetwork {
        self.network
    }

    pub fn security_domain_id(&self) -> &[u8; 32] {
        &self.security_domain_id
    }

    pub fn note_seed_commitment(&self) -> &[u8; 32] {
        &self.note_seed_commitment
    }

    /// The primary and mirror URL and required S3 owner for each HTTP request.
    pub fn publication_routes(&self) -> [(&Url, &str); 2] {
        self.publications
            .each_ref()
            .map(|row| (&row.endpoint, row.account.as_str()))
    }
}

/// Exact replica pins from a release accepted by both publication checks.
#[non_exhaustive]
pub struct NitroTarget {
    pub endpoint: Url,
    pub release_id: String,
    pub custody_epoch: u64,
    pub custody_digest: [u8; 32],
    pub executable_sha256: [u8; 32],
    pub pcrs: [[u8; 48]; 5],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NitroCheckpoint {
    pub sequence: u64,
    pub digest: [u8; 32],
    pub minimum_custody_epoch: u64,
    pub recovery_only: bool,
}

/// Both authenticated policy heads used by the next checkpoint transaction.
pub struct NitroPolicyUpdate<'a> {
    primary: &'a Head,
    mirror: &'a Head,
}

impl NitroPolicyUpdate<'_> {
    pub fn checkpoint(&self) -> &NitroCheckpoint {
        self.primary.policy.checkpoint()
    }

    /// Apply inside the same transaction that persists the primary checkpoint.
    pub fn advances(&self, current: Option<&NitroCheckpoint>) -> bool {
        current.is_none_or(|prior| {
            self.primary.follows(prior)
                && (self.mirror.policy.checkpoint.sequence < prior.sequence
                    || self.mirror.follows(prior))
        })
    }
}

pub struct AcceptedNitroPolicy {
    trust_fingerprint: [u8; 32],
    targets: Vec<NitroTarget>,
    checkpoint: NitroCheckpoint,
    valid_from_ms: u64,
    expires_at_ms: u64,
}

impl AcceptedNitroPolicy {
    pub fn targets(&self) -> &[NitroTarget] {
        &self.targets
    }

    pub fn checkpoint(&self) -> &NitroCheckpoint {
        &self.checkpoint
    }

    /// Check again before using a cached replica or accepting its response.
    pub fn require_current(
        &self,
        trust: &NitroTrust,
        store: &dyn NitroCheckpointStore,
        now_ms: u64,
    ) -> Result<(), NitroPolicyError> {
        self.require_current_with_clock(trust, store, || Ok(now_ms))
    }

    fn require_current_with_clock(
        &self,
        trust: &NitroTrust,
        store: &dyn NitroCheckpointStore,
        now: impl FnOnce() -> Result<u64, NitroPolicyError>,
    ) -> Result<(), NitroPolicyError> {
        if self.trust_fingerprint != trust.fingerprint {
            return Err(NitroPolicyError::Invalid);
        }
        if store.current(trust)?.as_ref() != Some(&self.checkpoint) {
            return Err(NitroPolicyError::Rollback);
        }
        self.require_valid_at(now()?)
    }

    pub(crate) fn require_valid_at(&self, now_ms: u64) -> Result<(), NitroPolicyError> {
        if (self.valid_from_ms..self.expires_at_ms).contains(&now_ms) {
            Ok(())
        } else {
            Err(NitroPolicyError::Invalid)
        }
    }
}

/// Validate both policy heads and durably accept the primary before returning any replica.
/// Callers fetching these themselves must use the pinned publication routes and owner headers.
pub fn accept_published_nitro_policy(
    trust: &NitroTrust,
    heads: [&[u8]; 2],
    store: &dyn NitroCheckpointStore,
    now_ms: u64,
) -> Result<AcceptedNitroPolicy, NitroPolicyError> {
    let [primary, mirror] = heads;
    let primary = verify_head(trust, primary)?;
    let mirror = verify_head(trust, mirror)?;
    if primary.policy.checkpoint.digest != mirror.policy.checkpoint.digest {
        let newer = &primary.policy.checkpoint;
        let prior = &mirror.policy.checkpoint;
        if prior.sequence.checked_add(1) != Some(newer.sequence)
            || !primary.follows(prior)
            || primary.policy.targets.iter().any(|target| {
                mirror.policy.targets.iter().any(|old| {
                    old.custody_epoch == target.custody_epoch
                        && old.custody_digest != target.custody_digest
                })
            })
        {
            return Err(NitroPolicyError::Invalid);
        }
    }
    let policy = &primary.policy;
    policy.require_valid_at(now_ms)?;
    if policy.checkpoint.sequence < trust.minimum_sequence
        || policy.checkpoint.minimum_custody_epoch < trust.minimum_custody_epoch
        || (trust.recovery_only && !policy.checkpoint.recovery_only)
    {
        return Err(NitroPolicyError::Invalid);
    }
    let update = NitroPolicyUpdate {
        primary: &primary,
        mirror: &mirror,
    };
    if !store.accept(trust, &update)? {
        return Err(NitroPolicyError::Rollback);
    }
    if policy.targets.is_empty() {
        return Err(NitroPolicyError::Revoked);
    }
    policy.require_current(trust, store, now_ms)?;
    Ok(primary.policy)
}

struct Head {
    policy: AcceptedNitroPolicy,
    previous: Option<[u8; 32]>,
}

impl Head {
    fn follows(&self, prior: &NitroCheckpoint) -> bool {
        let next = self.policy.checkpoint();
        if next.minimum_custody_epoch < prior.minimum_custody_epoch
            || (prior.recovery_only && !next.recovery_only)
        {
            return false;
        }
        if next.sequence == prior.sequence {
            return next == prior;
        }
        if prior.sequence.checked_add(1) == Some(next.sequence) {
            return self.previous == Some(prior.digest);
        }
        next.sequence > prior.sequence
    }
}

fn verify_head(trust: &NitroTrust, input: &[u8]) -> Result<Head, NitroPolicyError> {
    let signed: wire::Envelope =
        serde_json::from_slice(bounded(input)?).map_err(|_| NitroPolicyError::Invalid)?;
    let policy = signed.policy;
    let sequence = positive(&policy.sequence)?;
    let minimum_custody_epoch = positive(&policy.minimum_custody_epoch)?;
    let valid_from_ms = decimal(&policy.valid_from_ms)?;
    let expires_at_ms = decimal(&policy.expires_at_ms)?;
    let previous = policy
        .previous_policy_digest
        .as_deref()
        .map(identifier)
        .transpose()?;
    if policy.version != 1
        || policy.network != trust.network
        || identifier::<32>(&policy.security_domain_id)? != trust.security_domain_id
        || identifier::<32>(&policy.note_seed_commitment)? != trust.note_seed_commitment
        || (sequence == 1) != previous.is_none()
        || expires_at_ms <= valid_from_ms
        || expires_at_ms - valid_from_ms > MAX_LIFETIME_MS
        || policy.targets.len() > MAX_TARGETS
        || (policy.action == wire::Action::Revoke) != policy.targets.is_empty()
    {
        return Err(NitroPolicyError::Invalid);
    }
    let mut endpoints = BTreeSet::new();
    let mut records = BTreeMap::new();
    let targets = policy
        .targets
        .iter()
        .map(|target| {
            let target = target.decode(trust.network)?;
            if target.custody_epoch < minimum_custody_epoch
                || !endpoints.insert(target.endpoint.clone())
                || records
                    .insert(target.custody_epoch, target.custody_digest)
                    .is_some_and(|digest| digest != target.custody_digest)
            {
                return Err(NitroPolicyError::Invalid);
            }
            Ok(target)
        })
        .collect::<Result<_, _>>()?;
    // Every string is now canonical ASCII. Wire structs declare object fields in
    // RFC 8785 order and only the integer version and booleans are JSON scalars.
    let canonical = serde_json::to_vec(&policy).map_err(|_| NitroPolicyError::Invalid)?;
    let digest = signing_digest(RELEASE_DOMAIN, &canonical);
    let mut seen = BTreeSet::new();
    quorum(
        &signed.signatures,
        &trust.keys,
        trust.threshold,
        &digest,
        &mut seen,
    )?;
    quorum(
        &signed.custody_signatures,
        &trust.custody_keys,
        2,
        &signing_digest(CUSTODY_DOMAIN, &canonical),
        &mut seen,
    )?;
    if (sequence == trust.minimum_sequence && digest != trust.minimum_policy_digest)
        || (trust.minimum_sequence.checked_add(1) == Some(sequence)
            && previous != Some(trust.minimum_policy_digest))
    {
        return Err(NitroPolicyError::Invalid);
    }
    Ok(Head {
        policy: AcceptedNitroPolicy {
            trust_fingerprint: trust.fingerprint,
            valid_from_ms,
            expires_at_ms,
            targets,
            checkpoint: NitroCheckpoint {
                sequence,
                digest,
                minimum_custody_epoch,
                recovery_only: policy.recovery_only,
            },
        },
        previous,
    })
}

fn signing_digest(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical);
    hash.finalize().into()
}

fn quorum(
    signatures: &[wire::Signature],
    pins: &[[u8; 65]],
    threshold: usize,
    digest: &[u8; 32],
    seen: &mut BTreeSet<[u8; 65]>,
) -> Result<(), NitroPolicyError> {
    if !(threshold..=MAX_AUTHORITIES).contains(&signatures.len()) {
        return Err(NitroPolicyError::Invalid);
    }
    let mut approved = 0;
    for endorsement in signatures {
        let key = fixed(&endorsement.key)?;
        let signature = Signature::from_slice(&fixed::<64>(&endorsement.signature)?)
            .map_err(|_| NitroPolicyError::Invalid)?;
        if !seen.insert(key) || signature.normalize_s() != signature {
            return Err(NitroPolicyError::Invalid);
        }
        verifier(&key)?
            .verify_prehash(digest, &signature)
            .map_err(|_| NitroPolicyError::Invalid)?;
        approved += usize::from(pins.contains(&key));
    }
    if approved < threshold {
        return Err(NitroPolicyError::Invalid);
    }
    Ok(())
}

fn verifier(key: &[u8; 65]) -> Result<VerifyingKey, NitroPolicyError> {
    if key[0] != 4 {
        return Err(NitroPolicyError::Invalid);
    }
    VerifyingKey::from_sec1_bytes(key).map_err(|_| NitroPolicyError::Invalid)
}

fn publication(
    pin: wire::Publication,
    network: NitroNetwork,
    domain: &str,
) -> Result<Publication, NitroPolicyError> {
    let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bucket = pin.bucket.as_bytes();
    let region: Vec<_> = pin.region.split('-').collect();
    if !(3..=63).contains(&bucket.len())
        || !alnum(bucket[0])
        || !alnum(bucket[bucket.len() - 1])
        || !bucket.iter().all(|byte| *byte == b'-' || alnum(*byte))
        || region.len() != 3
        || region[0].len() != 2
        || region[1].is_empty()
        || !region[..2]
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_lowercase()))
        || positive(region[2]).is_err()
        || pin.account.len() != 12
        || !pin.account.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NitroPolicyError::Trust);
    }
    let endpoint = Url::parse(&format!(
        "https://{}.s3.{}.amazonaws.com/spr-release/{}/{domain}/policy.json",
        pin.bucket,
        pin.region,
        network.as_str(),
    ))
    .map_err(|_| NitroPolicyError::Trust)?;
    Ok(Publication {
        endpoint,
        account: pin.account,
    })
}

fn bounded(input: &[u8]) -> Result<&[u8], NitroPolicyError> {
    if input.len() <= MAX_POLICY_BYTES {
        Ok(input)
    } else {
        Err(NitroPolicyError::Invalid)
    }
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], NitroPolicyError> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| NitroPolicyError::Invalid)?;
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(NitroPolicyError::Invalid);
    }
    Ok(bytes)
}

fn identifier<const N: usize>(value: &str) -> Result<[u8; N], NitroPolicyError> {
    let bytes = fixed(value)?;
    if bytes == [0; N] {
        Err(NitroPolicyError::Invalid)
    } else {
        Ok(bytes)
    }
}

fn decimal(value: &str) -> Result<u64, NitroPolicyError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == value)
        .ok_or(NitroPolicyError::Invalid)
}

fn positive(value: &str) -> Result<u64, NitroPolicyError> {
    let number = decimal(value)?;
    if number > 0 {
        Ok(number)
    } else {
        Err(NitroPolicyError::Invalid)
    }
}

#[cfg(all(test, unix))]
#[path = "../tests/nitro_policy.rs"]
mod tests;
