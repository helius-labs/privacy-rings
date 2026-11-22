//! Wallet transport for the native Nitro decryption service.

mod crypto;
mod keys;
mod wire;

use std::{
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};

use futures::{stream::FuturesUnordered, StreamExt};
use reqwest::{header::CONTENT_TYPE, Client, StatusCode};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_api::{BlockingInsideRuntime, BlockingRuntime};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, X25519Pubkey};
use spr_transaction::DecryptRequest;
use thiserror::Error;
use tokio::{
    sync::{oneshot, Mutex, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    nitro_policy::{
        now_ms, read_limited, AcceptedNitroPolicy, NitroCheckpointStore, NitroNetwork,
        NitroPolicyError, NitroPolicyReader, NitroTarget, NitroTrust,
    },
    user_registry::{resolve_shielded_recipient, resolve_shielded_recipient_async},
    AsyncRpc, ClientError, Rpc,
};

pub use self::keys::NitroDecryptionKeys;
pub use crate::client::{NitroPaymentRecipient, NitroPaymentSubmission};

use self::{
    crypto::{random_bytes, response_secret, OVERHEAD},
    wire::{Attestation, Operation, OperationResult, Replica, Request, MAX_CIPHERTEXT},
};

const ATTESTATION_TIMEOUT: Duration = Duration::from_millis(3_500);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(12);
const PROBE_STAGGER_MS: u64 = 200;
const SESSION_MS: u64 = 60_000;
const OWNER_TIMEOUT: Duration = Duration::from_millis(SESSION_MS);
const MAX_ATTESTATION_BYTES: usize = 49_152;
const MAX_RESPONSE_BYTES: usize = 2 * MAX_CIPHERTEXT + 65_536;
const MAX_ITEMS: usize = 256;
type Owner = dyn Signer + Send + Sync;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NitroDecryptionError {
    #[error(transparent)]
    Policy(#[from] NitroPolicyError),
    #[error("no authorized Nitro replica could be attested")]
    Attestation,
    #[error("Nitro decryption transport is unavailable")]
    Unavailable,
    #[error("Nitro decryption returned HTTP {0}")]
    Http(StatusCode),
    #[error("invalid Nitro decryption message or proof")]
    Protocol,
    #[error("wallet signatures are required from a valid Ed25519 owner")]
    InvalidOwner,
    #[error("owner signature over the decryption request failed")]
    Signature,
    #[error("wallet signer did not finish before the authorization deadline")]
    OwnerTimeout,
    #[error("the attested decryption session expired")]
    SessionExpired,
    #[error("OS random generation failed")]
    Random,
    #[error("Nitro decryption only accepts recovery requests")]
    RecoveryOnly,
    #[error("the Solana RPC is on a different network from the decryption service")]
    NetworkMismatch,
    #[error("the transaction output does not match the resolved Nitro payment recipient")]
    PaymentRecipientMismatch,
    #[error("the Nitro payment recipient changed during transaction preparation")]
    PaymentRecipientChanged,
    #[error("the signer changed the prepared Nitro payment message")]
    PaymentMessageChanged,
    #[error("the encrypted decryption request exceeds the service limit")]
    RequestTooLarge,
    #[error(transparent)]
    Blocking(#[from] BlockingInsideRuntime),
}

/// Reads signed policy, attests a replica, and seals requests to the attested boot.
#[derive(Clone)]
pub struct NitroDecryptionService(Arc<Service>);

struct Service {
    http: Client,
    trust: Arc<NitroTrust>,
    policies: NitroPolicyReader,
    cache: Mutex<Cache>,
    owner_work: Arc<Semaphore>,
    blocking: OnceLock<BlockingRuntime>,
}

#[derive(Default)]
struct Cache {
    session: Option<Arc<Session>>,
    next_target: usize,
}

struct Session {
    policy: Arc<AcceptedNitroPolicy>,
    replica: Replica,
    endpoint: Url,
    window: SessionWindow,
}

#[derive(Clone, Copy)]
struct SessionWindow {
    expires_at_ms: u64,
    deadline: Instant,
}

impl SessionWindow {
    fn remaining(self, now_ms: u64) -> Duration {
        Duration::from_millis(self.expires_at_ms.saturating_sub(now_ms))
            .min(self.deadline.saturating_duration_since(Instant::now()))
    }

    fn require_current(self, now_ms: u64) -> Result<(), NitroDecryptionError> {
        if self.remaining(now_ms).is_zero() {
            return Err(NitroDecryptionError::SessionExpired);
        }
        Ok(())
    }
}

impl Session {
    fn approval_expires_at(&self, now: u64) -> u64 {
        let remaining_ms = self.window.remaining(now).as_millis() as u64;
        now.saturating_add(remaining_ms)
            .min(self.policy.expires_at_ms())
            .min(self.replica.valid_through_ms.saturating_add(1))
    }
}

impl NitroDecryptionService {
    pub fn new(
        trust: Arc<NitroTrust>,
        store: Arc<dyn NitroCheckpointStore>,
    ) -> Result<Self, NitroDecryptionError> {
        Ok(Self(Arc::new(Service {
            http: Client::builder()
                .timeout(OPERATION_TIMEOUT)
                .retry(reqwest::retry::never())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| NitroDecryptionError::Unavailable)?,
            policies: NitroPolicyReader::new(trust.clone(), store)?,
            trust,
            cache: Mutex::default(),
            owner_work: Arc::new(Semaphore::new(1)),
            blocking: OnceLock::new(),
        })))
    }

    /// Resolve keys for a new payment. Recovery-only domains refuse this call.
    pub async fn address(&self, owner: Pubkey) -> Result<ShieldedAddress, NitroDecryptionError> {
        self.address_with_retry(owner, true).await
    }

    /// Use the decryption service after a verified registry miss.
    pub async fn resolve_recipient<R: AsyncRpc>(
        &self,
        rpc: &R,
        owner: Pubkey,
    ) -> Result<NitroPaymentRecipient, ClientError> {
        let address = self.resolve_recipient_address(rpc, owner).await?;
        Ok(NitroPaymentRecipient::new(self.clone(), owner, address))
    }

    pub(crate) async fn resolve_recipient_address<R: AsyncRpc>(
        &self,
        rpc: &R,
        owner: Pubkey,
    ) -> Result<ShieldedAddress, ClientError> {
        resolve_shielded_recipient_async(rpc, owner, |owner| async move {
            self.require_chain(rpc.genesis_hash().await?)?;
            self.address(owner).await.map_err(ClientError::from)
        })
        .await
    }

    /// Blocking recipient resolution for wallets using a blocking Solana RPC.
    pub fn resolve_recipient_sync<R: Rpc>(
        &self,
        rpc: &R,
        owner: Pubkey,
    ) -> Result<NitroPaymentRecipient, ClientError> {
        let address = resolve_shielded_recipient(rpc, owner, |owner| {
            self.require_chain(rpc.genesis_hash()?)?;
            self.runtime()
                .block_on(self.address(owner))
                .map_err(ClientError::from)
        })?;
        Ok(NitroPaymentRecipient::new(self.clone(), owner, address))
    }

    fn require_chain(&self, genesis_hash: [u8; 32]) -> Result<(), NitroDecryptionError> {
        // Solana's complete 32-byte genesis hashes, encoded as base58.
        let expected = match self.0.trust.network() {
            NitroNetwork::Devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
            NitroNetwork::Mainnet => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        };
        if solana_hash::Hash::from(genesis_hash).to_string() != expected {
            return Err(NitroDecryptionError::NetworkMismatch);
        }
        Ok(())
    }

    fn runtime(&self) -> &BlockingRuntime {
        self.0.blocking.get_or_init(BlockingRuntime::new)
    }

    async fn address_with_retry(
        &self,
        owner: Pubkey,
        accepts_payment: bool,
    ) -> Result<ShieldedAddress, NitroDecryptionError> {
        wire::owner_key(owner)?;
        let result = retry_public_keys(async || {
            let (session, cached) = self.0.session().await?;
            if accepts_payment {
                let published = if cached {
                    Some(self.0.policies.read().await?)
                } else {
                    None
                };
                let policy = published.as_ref().unwrap_or(&session.policy);
                if policy.checkpoint().recovery_only {
                    return Err(NitroDecryptionError::RecoveryOnly);
                }
            }
            self.0
                .exchange(&session, Operation::public_keys(owner), None)
                .await
        })
        .await?;
        let OperationResult::PublicKeys {
            nullifier_public_key,
            viewing_public_key,
        } = result
        else {
            return Err(NitroDecryptionError::Protocol);
        };
        let nullifier_pubkey = wire::fixed(&nullifier_public_key)?;
        if !is_canonical_bn254_scalar_be(&nullifier_pubkey) {
            return Err(NitroDecryptionError::Protocol);
        }
        Ok(ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(&owner.to_bytes()),
            viewing_pubkey: X25519Pubkey::from_bytes(wire::fixed(&viewing_public_key)?)
                .map_err(|_| NitroDecryptionError::Protocol)?,
            nullifier_pubkey,
        })
    }

    async fn decrypt_batch(
        &self,
        owner: Pubkey,
        signer: Arc<Owner>,
        items: &[DecryptRequest<'_>],
    ) -> Result<(NullifierKey, Zeroizing<Vec<Vec<u8>>>), NitroDecryptionError> {
        if items.len() > MAX_ITEMS
            || items
                .iter()
                .try_fold(0usize, |total, item| {
                    total
                        .checked_add(item.ciphertext.len())
                        .filter(|size| *size <= MAX_CIPHERTEXT / 4)
                })
                .is_none()
        {
            return Err(NitroDecryptionError::RequestTooLarge);
        }
        let (session, _) = self.0.session().await?;
        let now = now_ms()?;
        let expires_at_ms = session.approval_expires_at(now);
        if expires_at_ms <= now {
            return Err(NitroDecryptionError::SessionExpired);
        }
        let result = self
            .0
            .exchange(
                &session,
                Operation::decrypt(owner, items, expires_at_ms),
                Some((owner, signer)),
            )
            .await;
        let (nullifier_secret, plaintexts) = match result {
            Ok(OperationResult::Decrypt {
                nullifier_secret,
                plaintexts,
            }) if plaintexts.len() == items.len() => (nullifier_secret, plaintexts),
            Err(error) => return Err(error),
            _ => return Err(NitroDecryptionError::Protocol),
        };
        let mut secret = Zeroizing::new([0; 31]);
        wire::decode(&nullifier_secret.0, secret.as_mut())?;
        let mut decoded = Zeroizing::new(Vec::with_capacity(items.len()));
        for (plaintext, item) in plaintexts.iter().zip(items) {
            let mut bytes = Zeroizing::new(vec![0; item.ciphertext.len()]);
            wire::decode(&plaintext.0, bytes.as_mut())?;
            decoded.push(std::mem::take(&mut *bytes));
        }
        Ok((NullifierKey::from_secret(*secret), decoded))
    }
}

async fn retry_public_keys<T>(
    mut call: impl AsyncFnMut() -> Result<T, NitroDecryptionError>,
) -> Result<T, NitroDecryptionError> {
    let result = call().await;
    if result.as_ref().is_err_and(recoverable) {
        return call().await;
    }
    result
}

fn recoverable(error: &NitroDecryptionError) -> bool {
    match error {
        NitroDecryptionError::Unavailable
        | NitroDecryptionError::Protocol
        | NitroDecryptionError::SessionExpired
        | NitroDecryptionError::Policy(NitroPolicyError::Superseded) => true,
        NitroDecryptionError::Http(status) => {
            status.is_server_error()
                || [StatusCode::BAD_REQUEST, StatusCode::REQUEST_TIMEOUT].contains(status)
        }
        _ => false,
    }
}

async fn owner_call<T: Send + 'static>(
    worker: &Arc<Semaphore>,
    timeout: Duration,
    check: impl Future<Output = Result<(), NitroDecryptionError>>,
    call: impl FnOnce() -> Result<T, NitroDecryptionError> + Send + 'static,
) -> Result<T, NitroDecryptionError> {
    let deadline = Instant::now() + timeout;
    let permit = timeout_at(deadline, worker.clone().acquire_owned())
        .await
        .map_err(|_| NitroDecryptionError::OwnerTimeout)?
        .map_err(|_| NitroDecryptionError::Signature)?;
    timeout_at(deadline, check)
        .await
        .map_err(|_| NitroDecryptionError::OwnerTimeout)??;
    let (reply, result) = oneshot::channel();
    // Keep a stalled device off Tokio's blocking pool so it cannot hold up runtime shutdown.
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("spr-nitro-signer".into())
        .spawn(move || {
            let _permit = permit;
            let _runtime = runtime.enter();
            if !reply.is_closed() && Instant::now() < deadline {
                let _ = reply.send(call());
            }
        })
        .map_err(|_| NitroDecryptionError::Signature)?;
    let result = timeout_at(deadline, result)
        .await
        .map_err(|_| NitroDecryptionError::OwnerTimeout)?;
    if Instant::now() >= deadline {
        return Err(NitroDecryptionError::OwnerTimeout);
    }
    result.map_err(|_| NitroDecryptionError::Signature)?
}

#[cfg(test)]
#[path = "../tests/nitro_owner.rs"]
mod owner_tests;

impl Service {
    async fn session(&self) -> Result<(Arc<Session>, bool), NitroDecryptionError> {
        let mut cache = self.cache.lock().await;
        if let Some(session) = &cache.session {
            if self.require_current(session).await.is_ok() {
                return Ok((session.clone(), true));
            }
        }

        cache.session = None;
        let window = SessionWindow {
            expires_at_ms: now_ms()?.saturating_add(SESSION_MS),
            deadline: Instant::now() + Duration::from_millis(SESSION_MS),
        };
        let (session, index) = timeout_at(window.deadline, self.connect(cache.next_target, window))
            .await
            .map_err(|_| NitroDecryptionError::SessionExpired)??;
        cache.next_target = index + 1;
        cache.session = Some(session.clone());
        Ok((session, false))
    }

    async fn connect(
        &self,
        next_target: usize,
        window: SessionWindow,
    ) -> Result<(Arc<Session>, usize), NitroDecryptionError> {
        let policy = Arc::new(self.policies.read().await?);
        window.require_current(now_ms()?)?;
        let targets = policy.targets();
        let count = targets.len();
        let start = next_target % count;
        let mut probes = (0..count)
            .map(|offset| {
                let index = (start + offset) % count;
                let target = &targets[index];
                let policy = policy.clone();
                async move {
                    if offset > 0 {
                        tokio::time::sleep(Duration::from_millis(offset as u64 * PROBE_STAGGER_MS))
                            .await;
                    }
                    self.attest(policy, target, window)
                        .await
                        .map(|replica| (index, replica))
                }
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(candidate) = probes.next().await {
            match candidate {
                Ok((index, replica)) => {
                    let session = Arc::new(Session {
                        policy: policy.clone(),
                        endpoint: targets[index].endpoint.clone(),
                        replica,
                        window,
                    });
                    self.require_current(&session).await?;
                    return Ok((session, index));
                }
                Err(
                    error @ (NitroDecryptionError::SessionExpired
                    | NitroDecryptionError::Policy(NitroPolicyError::Superseded)),
                ) => return Err(error),
                Err(_) => (),
            }
        }
        self.require_fresh_policy(&policy, window).await?;
        Err(NitroDecryptionError::Attestation)
    }

    async fn require_fresh_policy(
        &self,
        policy: &Arc<AcceptedNitroPolicy>,
        window: SessionWindow,
    ) -> Result<u64, NitroDecryptionError> {
        window.require_current(now_ms()?)?;
        timeout_at(
            window.deadline,
            self.policies.require_current(policy.clone()),
        )
        .await
        .map_err(|_| NitroDecryptionError::SessionExpired)??;
        let now = now_ms()?;
        policy.require_valid_at(now)?;
        window.require_current(now)?;
        Ok(now)
    }

    async fn require_current(&self, session: &Session) -> Result<(), NitroDecryptionError> {
        let now = self
            .require_fresh_policy(&session.policy, session.window)
            .await?;
        if !(session.replica.valid_from_ms..=session.replica.valid_through_ms).contains(&now) {
            return Err(NitroDecryptionError::SessionExpired);
        }
        Ok(())
    }

    async fn require_exchange_policy(
        &self,
        session: &Session,
        approval_expires_at_ms: Option<u64>,
    ) -> Result<(), NitroDecryptionError> {
        self.require_current(session).await?;
        if let Some(expires_at_ms) = approval_expires_at_ms {
            let now = now_ms()?;
            require_unexpired_approval(approval_expires_at_ms, now)?;
            let remaining =
                Duration::from_millis(expires_at_ms - now).min(session.window.remaining(now));
            timeout(remaining, self.policies.read())
                .await
                .map_err(|_| NitroDecryptionError::SessionExpired)??;
            self.require_current(session).await?;
            require_unexpired_approval(approval_expires_at_ms, now_ms()?)?;
        }
        Ok(())
    }

    async fn forget(&self, session: &Arc<Session>) {
        let mut cache = self.cache.lock().await;
        if cache
            .session
            .as_ref()
            .is_some_and(|other| Arc::ptr_eq(other, session))
        {
            cache.session = None;
        }
    }

    async fn attest(
        &self,
        policy: Arc<AcceptedNitroPolicy>,
        target: &NitroTarget,
        window: SessionWindow,
    ) -> Result<Replica, NitroDecryptionError> {
        let nonce: [u8; 32] = random_bytes()?;
        self.require_fresh_policy(&policy, window).await?;
        let response = self
            .http
            .post(route(&target.endpoint, &["v1", "nitro", "attestation"])?)
            .timeout(ATTESTATION_TIMEOUT)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(nonce.to_vec())
            .send()
            .await
            .map_err(|_| NitroDecryptionError::Unavailable)?;
        let value: Attestation =
            serde_json::from_slice(&body(response, MAX_ATTESTATION_BYTES).await?)
                .map_err(|_| NitroDecryptionError::Attestation)?;
        value.verify(&self.trust, target, &nonce, now_ms()?)
    }

    async fn exchange(
        &self,
        session: &Arc<Session>,
        operation: Operation,
        signer: Option<(Pubkey, Arc<Owner>)>,
    ) -> Result<OperationResult, NitroDecryptionError> {
        let result = self.exchange_on_boot(session, operation, signer).await;
        if result.as_ref().is_err_and(recoverable) {
            self.forget(session).await;
        }
        result
    }

    async fn exchange_on_boot(
        &self,
        session: &Session,
        operation: Operation,
        signer: Option<(Pubkey, Arc<Owner>)>,
    ) -> Result<OperationResult, NitroDecryptionError> {
        self.require_current(session).await?;
        let approval_expires_at_ms = operation.approval_expires_at_ms();
        let response_secret = response_secret()?;
        let request_id = random_bytes()?;
        let mut request = Request::new(
            &session.replica.info,
            &request_id,
            &response_secret.public_key(),
            operation,
        );
        let digest = request.unsigned_digest()?;
        let envelope_overhead = request.envelope(&[])?.len() + 2 * OVERHEAD;
        if signer.is_some() {
            request.set_signature(&[0; 64]);
        }
        let size = wire::json(&request)?.len();
        if envelope_overhead + 2 * size > MAX_CIPHERTEXT {
            return Err(NitroDecryptionError::RequestTooLarge);
        }
        if let (Some((owner, signer)), Some(expires_at_ms)) = (signer, approval_expires_at_ms) {
            let key = wire::owner_key(owner)?;
            let message = wire::owner_message(&key, self.trust.network(), &digest);
            let now = now_ms()?;
            let timeout = Duration::from_millis(expires_at_ms.saturating_sub(now))
                .min(session.window.remaining(now));
            let signature = owner_call(
                &self.owner_work,
                timeout,
                self.require_exchange_policy(session, approval_expires_at_ms),
                move || {
                    let signature: [u8; 64] = signer
                        .try_sign_message(&message)
                        .map_err(|_| NitroDecryptionError::Signature)?
                        .into();
                    wire::verify_owner(&key, &message, &signature)?;
                    Ok(signature)
                },
            )
            .await?;
            request.set_signature(&signature);
        }
        let plaintext = Zeroizing::new(wire::json(&request)?);
        let sealed = crypto::seal(&session.replica.encryption, &plaintext)?;
        let encrypted = request.envelope(&sealed)?;
        if encrypted.len() > MAX_CIPHERTEXT {
            return Err(NitroDecryptionError::RequestTooLarge);
        }
        self.require_exchange_policy(session, approval_expires_at_ms)
            .await?;
        let response = self
            .http
            .post(route(&session.endpoint, &["v1", "operations"])?)
            .header(CONTENT_TYPE, "application/json")
            .body(encrypted)
            .send()
            .await
            .map_err(|_| NitroDecryptionError::Unavailable)?;
        let response = serde_json::from_slice(&body(response, MAX_RESPONSE_BYTES).await?)
            .map_err(|_| NitroDecryptionError::Protocol)?;
        let ciphertext = request.verify_response(&session.replica, response, &digest)?;
        self.require_exchange_policy(session, approval_expires_at_ms)
            .await?;
        let plaintext = crypto::open(&response_secret, &ciphertext)?;
        serde_json::from_slice(&plaintext).map_err(|_| NitroDecryptionError::Protocol)
    }
}

fn require_unexpired_approval(
    expires_at_ms: Option<u64>,
    now: u64,
) -> Result<(), NitroDecryptionError> {
    if expires_at_ms.is_some_and(|expires_at_ms| now >= expires_at_ms) {
        return Err(NitroDecryptionError::SessionExpired);
    }
    Ok(())
}

async fn body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, NitroDecryptionError> {
    if !response.status().is_success() {
        return Err(NitroDecryptionError::Http(response.status()));
    }
    read_limited(response, limit)
        .await
        .map_err(|error| match error {
            NitroPolicyError::Unavailable => NitroDecryptionError::Unavailable,
            _ => NitroDecryptionError::Protocol,
        })
}

fn route(endpoint: &Url, path: &[&str]) -> Result<Url, NitroDecryptionError> {
    let mut url = endpoint.clone();
    url.path_segments_mut()
        .map_err(|_| NitroDecryptionError::Protocol)?
        .pop_if_empty()
        .extend(path);
    Ok(url)
}
