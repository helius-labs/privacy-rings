use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::{identifier, positive, NitroNetwork, NitroPolicyError, NitroTarget};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Trust {
    pub(super) network: NitroNetwork,
    pub(super) security_domain_id: String,
    pub(super) note_seed_commitment: String,
    pub(super) minimum_custody_epoch: String,
    pub(super) minimum_sequence: String,
    pub(super) minimum_policy_digest: String,
    #[serde(default)]
    pub(super) recovery_only: bool,
    pub(super) publications: [Publication; 2],
    pub(super) threshold: usize,
    pub(super) keys: Vec<String>,
    pub(super) custody_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    pub(super) bucket: String,
    pub(super) region: String,
    pub(super) account: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Envelope {
    pub(super) policy: Policy,
    pub(super) signatures: Vec<Signature>,
    pub(super) custody_signatures: Vec<Signature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signature {
    pub(super) key: String,
    pub(super) signature: String,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Action {
    Activate,
    Revoke,
}

// Keep the signed structs in lexicographic JSON key order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Policy {
    pub(super) action: Action,
    pub(super) expires_at_ms: String,
    pub(super) minimum_custody_epoch: String,
    pub(super) network: NitroNetwork,
    pub(super) note_seed_commitment: String,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) previous_policy_digest: Option<String>,
    pub(super) recovery_only: bool,
    pub(super) security_domain_id: String,
    pub(super) sequence: String,
    pub(super) targets: Vec<Target>,
    pub(super) valid_from_ms: String,
    pub(super) version: u8,
}

fn required_nullable<'de, D: Deserializer<'de>>(decoder: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(decoder)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Target {
    custody_digest: String,
    custody_epoch: String,
    endpoint: String,
    executable_sha256: String,
    pcrs: Pcrs,
    release_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pcrs {
    #[serde(rename = "0")]
    image: String,
    #[serde(rename = "1")]
    kernel: String,
    #[serde(rename = "2")]
    app: String,
    #[serde(rename = "3")]
    role: String,
    #[serde(rename = "4")]
    parent: String,
}

impl Target {
    pub(super) fn decode(&self, network: NitroNetwork) -> Result<NitroTarget, NitroPolicyError> {
        if self.endpoint.len() > 512
            || !self.endpoint.is_ascii()
            || !(1..=64).contains(&self.release_id.len())
            || !self.release_id.bytes().next().is_some_and(alnum)
            || !self.release_id.bytes().all(|b| b == b'-' || alnum(b))
        {
            return Err(NitroPolicyError::Invalid);
        }
        let endpoint = Url::parse(&self.endpoint).map_err(|_| NitroPolicyError::Invalid)?;
        let loopback = network == NitroNetwork::Devnet
            && endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"));
        if endpoint.as_str() != self.endpoint
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !(endpoint.scheme() == "https" || loopback)
        {
            return Err(NitroPolicyError::Invalid);
        }
        Ok(NitroTarget {
            endpoint,
            release_id: self.release_id.clone(),
            custody_epoch: positive(&self.custody_epoch)?,
            executable_sha256: identifier(&self.executable_sha256)?,
            custody_digest: identifier(&self.custody_digest)?,
            pcrs: [
                identifier(&self.pcrs.image)?,
                identifier(&self.pcrs.kernel)?,
                identifier(&self.pcrs.app)?,
                identifier(&self.pcrs.role)?,
                identifier(&self.pcrs.parent)?,
            ],
        })
    }
}

fn alnum(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}
