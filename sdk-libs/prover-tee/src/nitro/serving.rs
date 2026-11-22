use ciborium::Value;

use super::{
    authenticate, capped, invalid, malformed, AttestationUse, AWS_NITRO_ROOT_G1, COSE_SIGN1_TAG,
};
use crate::TeeError;

const MAX_SERVING_EVIDENCE_BYTES: usize = 16_384;
const SERVING_CLOCK_SKEW_MS: u64 = 60_000;
const P256_POINT_BYTES: usize = 65;

/// Measurements and challenge for one standalone decryption replica.
pub struct NitroServingPins<'a> {
    pub pcrs: &'a [[u8; 48]; 5],
    pub nonce: &'a [u8; 32],
    /// SHA-256 of the protocol domain and the canonical discovery payload.
    pub discovery_binding: &'a [u8; 32],
}

/// Authenticated replica keys and the certificate interval for this boot.
#[non_exhaustive]
pub struct VerifiedNitroServingBoot {
    pub public_keys: [u8; 2 * P256_POINT_BYTES],
    pub attested_at_ms: u64,
    pub certificate_valid_from_ms: u64,
    pub certificate_valid_through_ms: u64,
}

/// Verifies a fresh serving boot against the AWS Nitro root and the exact wallet pins.
///
/// Use measurements from the authenticated release policy, a local random nonce,
/// and a digest computed from the reply's canonical discovery object. The caller
/// validates the release and discovery fields and enforces the returned certificate
/// interval while using the boot.
pub fn verify_nitro_serving_boot(
    evidence: &[u8],
    pins: NitroServingPins<'_>,
    now_ms: u64,
) -> Result<VerifiedNitroServingBoot, TeeError> {
    verify_serving_boot(evidence, pins, now_ms, AWS_NITRO_ROOT_G1)
}

pub(super) fn verify_serving_boot(
    evidence: &[u8],
    pins: NitroServingPins<'_>,
    now_ms: u64,
    root: &[u8],
) -> Result<VerifiedNitroServingBoot, TeeError> {
    capped(
        evidence.len(),
        MAX_SERVING_EVIDENCE_BYTES,
        "serving evidence",
    )?;
    let (document, window) = authenticate(evidence, root, now_ms, AttestationUse::Serving)?;
    if document.timestamp == 0 || now_ms.abs_diff(document.timestamp) > SERVING_CLOCK_SKEW_MS {
        return Err(invalid("serving evidence is outside the freshness window"));
    }
    if document.nonce.as_deref() != Some(pins.nonce.as_slice())
        || document.user_data.as_deref() != Some(pins.discovery_binding.as_slice())
    {
        return Err(invalid(
            "serving challenge or discovery binding does not match",
        ));
    }
    for (index, pin) in pins.pcrs.iter().enumerate() {
        if *pin == [0u8; 48] || document.pcr(index)? != *pin {
            return Err(invalid(format!(
                "serving PCR{index} does not match its pin"
            )));
        }
    }
    let public_keys: [u8; 2 * P256_POINT_BYTES] = document
        .public_key
        .as_deref()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| invalid("the serving key pair is missing or has the wrong size"))?;
    for point in public_keys.chunks_exact(P256_POINT_BYTES) {
        if point[0] != 4 || p256::PublicKey::from_sec1_bytes(point).is_err() {
            return Err(invalid("a serving key is not an uncompressed P256 point"));
        }
    }
    Ok(VerifiedNitroServingBoot {
        public_keys,
        attested_at_ms: document.timestamp,
        certificate_valid_from_ms: window.not_before_ms + 1,
        certificate_valid_through_ms: window.not_after_ms - 1,
    })
}

pub(super) fn check_headers(evidence: &[u8]) -> Result<(), TeeError> {
    let value: Value = ciborium::from_reader(evidence).map_err(|_| malformed())?;
    let cose = match &value {
        Value::Tag(COSE_SIGN1_TAG, value) => value.as_ref(),
        value => value,
    };
    if let Some([Value::Bytes(protected), Value::Map(unprotected), _, _]) =
        cose.as_array().map(Vec::as_slice)
    {
        if unprotected.is_empty() {
            let headers: Value =
                ciborium::from_reader(protected.as_slice()).map_err(|_| malformed())?;
            if headers.as_map().is_some_and(|entries| {
                entries.as_slice() == [(Value::Integer(1.into()), Value::Integer((-35).into()))]
            }) {
                return Ok(());
            }
        }
    }
    Err(invalid("serving evidence has unexpected COSE headers"))
}
