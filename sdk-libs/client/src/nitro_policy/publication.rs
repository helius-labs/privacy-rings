use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::{header::CACHE_CONTROL, Client};
use url::Url;

use super::{
    accept_verified_heads, persist_checkpoint, verify_head, AcceptedNitroPolicy, Head,
    NitroCheckpoint, NitroCheckpointStore, NitroPolicyError, NitroPolicyUpdate, NitroTrust,
    MAX_POLICY_BYTES,
};

struct ObservedHead {
    verified: Result<Head, NitroPolicyError>,
    before_stop: [Option<NitroCheckpoint>; 2],
}

/// Reads the two fixed S3 publications with one deadline and no redirects.
pub struct NitroPolicyReader {
    client: Client,
    trust: Arc<NitroTrust>,
    store: Arc<dyn NitroCheckpointStore>,
    latest: Arc<Mutex<Option<NitroCheckpoint>>>,
    #[cfg(test)]
    pub(crate) test_heads: Mutex<Option<[Vec<u8>; 2]>>,
}

impl NitroPolicyReader {
    pub fn new(
        trust: Arc<NitroTrust>,
        store: Arc<dyn NitroCheckpointStore>,
    ) -> Result<Self, NitroPolicyError> {
        let client = Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| NitroPolicyError::Unavailable)?;
        Ok(Self {
            client,
            trust,
            store,
            latest: Arc::default(),
            #[cfg(test)]
            test_heads: Mutex::default(),
        })
    }

    /// Authentication and persistent storage finish before returning replica pins.
    pub async fn read(&self) -> Result<AcceptedNitroPolicy, NitroPolicyError> {
        #[cfg(test)]
        {
            let heads = self.test_heads.lock().unwrap().clone();
            if let Some([primary, mirror]) = heads {
                return self
                    .read_pair(
                        std::future::ready(Ok(primary)),
                        std::future::ready(Ok(mirror)),
                    )
                    .await;
            }
        }
        let [(primary, primary_owner), (mirror, mirror_owner)] = self.trust.publication_routes();
        self.read_pair(
            self.fetch(primary, primary_owner),
            self.fetch(mirror, mirror_owner),
        )
        .await
    }

    pub(crate) async fn read_pair(
        &self,
        primary: impl Future<Output = Result<Vec<u8>, NitroPolicyError>>,
        mirror: impl Future<Output = Result<Vec<u8>, NitroPolicyError>>,
    ) -> Result<AcceptedNitroPolicy, NitroPolicyError> {
        let (primary, mirror) =
            tokio::try_join!(self.observe_head(primary), self.observe_head(mirror))?;
        let trust = self.trust.clone();
        let store = self.store.clone();
        let latest = self.latest.clone();
        let policy = tokio::task::spawn_blocking(move || {
            let policy = {
                let mut latest = latest.lock().map_err(|_| NitroPolicyError::Storage)?;
                accept_verified_heads(
                    &trust,
                    [primary.verified, mirror.verified],
                    &*store,
                    now_ms()?,
                    &mut latest,
                    primary
                        .before_stop
                        .into_iter()
                        .chain(mirror.before_stop)
                        .flatten(),
                )?
            };
            require_current(&policy, &trust, &*store, &latest, now_ms)?;
            Ok(policy)
        })
        .await
        .map_err(|_| NitroPolicyError::Storage)??;
        policy.require_valid_at(now_ms()?)?;
        Ok(policy)
    }

    async fn observe_head(
        &self,
        read: impl Future<Output = Result<Vec<u8>, NitroPolicyError>>,
    ) -> Result<ObservedHead, NitroPolicyError> {
        let bytes = match read.await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Ok(ObservedHead {
                    verified: Err(error),
                    before_stop: [None, None],
                })
            }
        };
        let trust = self.trust.clone();
        let store = self.store.clone();
        let latest = self.latest.clone();
        // A verified stop can finish checkpointing if the caller cancels while its peer stalls.
        tokio::task::spawn_blocking(move || {
            let verified = verify_head(&trust, &bytes);
            let mut before_stop = [None, None];
            if let Ok(revocation) = &verified {
                if revocation.policy.checkpoint().revoked
                    && revocation.policy.current_under(&trust, now_ms()?)
                {
                    let mut latest = latest.lock().map_err(|_| NitroPolicyError::Storage)?;
                    before_stop = [store.current(&trust)?, latest.clone()];
                    persist_checkpoint(
                        &trust,
                        &*store,
                        &mut latest,
                        NitroPolicyUpdate {
                            primary: revocation,
                            mirror: None,
                        },
                    )?;
                }
            }
            Ok(ObservedHead {
                verified,
                before_stop,
            })
        })
        .await
        .map_err(|_| NitroPolicyError::Storage)?
    }

    pub(crate) async fn require_current(
        &self,
        policy: Arc<AcceptedNitroPolicy>,
    ) -> Result<(), NitroPolicyError> {
        let trust = self.trust.clone();
        let store = self.store.clone();
        let latest = self.latest.clone();
        tokio::task::spawn_blocking(move || {
            require_current(&policy, &trust, &*store, &latest, now_ms)
        })
        .await
        .map_err(|_| NitroPolicyError::Storage)?
    }

    async fn fetch(&self, endpoint: &Url, owner: &str) -> Result<Vec<u8>, NitroPolicyError> {
        let response = self
            .client
            .get(endpoint.clone())
            .header(CACHE_CONTROL, "no-cache")
            .header("x-amz-expected-bucket-owner", owner)
            .send()
            .await
            .map_err(|_| NitroPolicyError::Unavailable)?;
        if !response.status().is_success() {
            return Err(NitroPolicyError::Unavailable);
        }
        read_limited(response, MAX_POLICY_BYTES).await
    }
}

pub(super) fn require_current(
    policy: &AcceptedNitroPolicy,
    trust: &NitroTrust,
    store: &dyn NitroCheckpointStore,
    latest: &Mutex<Option<NitroCheckpoint>>,
    now: impl FnOnce() -> Result<u64, NitroPolicyError>,
) -> Result<(), NitroPolicyError> {
    policy.require_current_with_clock(trust, store, || {
        if latest
            .lock()
            .map_err(|_| NitroPolicyError::Storage)?
            .as_ref()
            .is_some_and(|checkpoint| checkpoint != policy.checkpoint())
        {
            return Err(NitroPolicyError::Superseded);
        }
        now()
    })
}

pub(crate) async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, NitroPolicyError> {
    if response
        .content_length()
        .is_some_and(|bytes| bytes > limit as u64)
    {
        return Err(NitroPolicyError::Invalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| NitroPolicyError::Unavailable)?
    {
        if chunk.len() > limit - body.len() {
            return Err(NitroPolicyError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn now_ms() -> Result<u64, NitroPolicyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(NitroPolicyError::Invalid)
}
