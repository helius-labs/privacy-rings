use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::{header::CACHE_CONTROL, Client};
use url::Url;

use super::{
    accept_published_nitro_policy, AcceptedNitroPolicy, NitroCheckpointStore, NitroPolicyError,
    NitroTrust, MAX_POLICY_BYTES,
};

/// Reads the two fixed S3 publications with one deadline and no redirects.
pub struct NitroPolicyReader {
    client: Client,
    trust: Arc<NitroTrust>,
    store: Arc<dyn NitroCheckpointStore>,
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
        })
    }

    /// Authentication and persistent storage finish before returning replica pins.
    pub async fn read(&self) -> Result<AcceptedNitroPolicy, NitroPolicyError> {
        let [(primary, primary_owner), (mirror, mirror_owner)] = self.trust.publication_routes();
        let (primary, mirror) = tokio::try_join!(
            self.fetch(primary, primary_owner),
            self.fetch(mirror, mirror_owner),
        )?;
        let trust = self.trust.clone();
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let policy =
                accept_published_nitro_policy(&trust, [&primary, &mirror], &*store, now_ms()?)?;
            policy.require_current(&trust, &*store, now_ms()?)?;
            Ok(policy)
        })
        .await
        .map_err(|_| NitroPolicyError::Storage)?
    }

    async fn fetch(&self, endpoint: &Url, owner: &str) -> Result<Vec<u8>, NitroPolicyError> {
        let mut response = self
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
        if response
            .content_length()
            .is_some_and(|bytes| bytes > MAX_POLICY_BYTES as u64)
        {
            return Err(NitroPolicyError::Invalid);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| NitroPolicyError::Unavailable)?
        {
            if chunk.len() > MAX_POLICY_BYTES - body.len() {
                return Err(NitroPolicyError::Invalid);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn now_ms() -> Result<u64, NitroPolicyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(NitroPolicyError::Invalid)
}
