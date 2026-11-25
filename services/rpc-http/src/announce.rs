//! Announces the methods a service serves to a registry that forwards them.

use std::{
    convert::Infallible,
    fmt::Display,
    future::{ready, Future},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use spr_indexer_api::{
    method::AnnounceUpstream, AnnounceUpstreamRequest, AnnounceUpstreamResponse, RpcMethod,
    UpstreamAnnouncement,
};
use thiserror::Error;

use crate::forward::UpstreamUrl;

/// Each announcement carries a later second than the one before.
const INTERVAL: Duration = Duration::from_secs(30);

pub struct Announcer {
    pub registry: UpstreamUrl,
    /// Where the registry reaches this service.
    pub url: UpstreamUrl,
    pub methods: Vec<String>,
    pub pubkey: Pubkey,
}

#[derive(Debug, Error)]
pub enum AnnounceError {
    #[error("the registry did not answer")]
    Http(#[from] reqwest::Error),
    #[error("the registry refused the announcement, {0}")]
    Refused(String),
    #[error("the announcement was not signed, {0}")]
    Unsigned(String),
}

#[derive(Deserialize)]
struct Answer {
    result: Option<AnnounceUpstreamResponse>,
    error: Option<Refusal>,
}

#[derive(Deserialize)]
struct Refusal {
    message: String,
}

impl Announcer {
    /// `sign` is Ed25519 under `pubkey`.
    pub fn spawn(
        self,
        sign: impl Fn(&[u8]) -> Signature + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_with(move |message| ready(Ok::<_, Infallible>(sign(&message))))
    }

    /// A signer outside the process, a failed signature skips one announcement.
    pub fn spawn_with<Sign, Signing, Failure>(self, sign: Sign) -> tokio::task::JoinHandle<()>
    where
        Sign: Fn(Vec<u8>) -> Signing + Send + Sync + 'static,
        Signing: Future<Output = Result<Signature, Failure>> + Send,
        Failure: Display,
    {
        tokio::spawn(async move {
            let http = reqwest::Client::new();
            let mut last = None;
            loop {
                let outcome = self
                    .announce_with(&http, &sign)
                    .await
                    .map_err(|error| error.to_string());
                if last.as_ref() != Some(&outcome) {
                    match &outcome {
                        Ok(true) => log::info!("{} forwards to {}", self.registry, self.url),
                        Ok(false) => log::warn!(
                            "{} waits for an operator to approve {} at {}",
                            self.registry,
                            self.pubkey,
                            self.url
                        ),
                        Err(error) => log::warn!("{error}"),
                    }
                    last = Some(outcome);
                }
                tokio::time::sleep(INTERVAL).await;
            }
        })
    }

    /// Whether the registry forwards to the announced URL.
    pub async fn announce(
        &self,
        http: &reqwest::Client,
        sign: &impl Fn(&[u8]) -> Signature,
    ) -> Result<bool, AnnounceError> {
        self.announce_with(http, &|message: Vec<u8>| {
            ready(Ok::<_, Infallible>(sign(&message)))
        })
        .await
    }

    pub async fn announce_with<Sign, Signing, Failure>(
        &self,
        http: &reqwest::Client,
        sign: &Sign,
    ) -> Result<bool, AnnounceError>
    where
        Sign: Fn(Vec<u8>) -> Signing,
        Signing: Future<Output = Result<Signature, Failure>>,
        Failure: Display,
    {
        let announcement = UpstreamAnnouncement {
            url: self.url.as_str().to_owned(),
            methods: self.methods.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        };
        let signature = sign(announcement.message().to_vec())
            .await
            .map_err(|failure| AnnounceError::Unsigned(failure.to_string()))?;
        let request = AnnounceUpstreamRequest {
            pubkey: self.pubkey.into(),
            signature: signature.into(),
            announcement,
        };
        let answer: Answer = http
            .post(format!(
                "{}/{}",
                self.registry.as_str(),
                AnnounceUpstream::NAME
            ))
            .timeout(INTERVAL)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": AnnounceUpstream::NAME,
                "params": request,
            }))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?
            .json()
            .await
            .map_err(reqwest::Error::without_url)?;
        match (answer.result, answer.error) {
            (Some(result), _) => Ok(result.approved),
            (None, error) => Err(AnnounceError::Refused(
                error.map_or_else(String::new, |error| error.message),
            )),
        }
    }
}
