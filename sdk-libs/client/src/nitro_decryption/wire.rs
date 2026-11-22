use ed25519_dalek::{Signature as OwnerSignature, VerifyingKey as OwnerKey};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToSec1Point,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use spr_prover_tee::{verify_nitro_serving_boot, NitroServingPins};
use spr_transaction::{DecryptLabel, DecryptRequest};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nitro_policy::{NitroNetwork, NitroTarget, NitroTrust};

use super::{
    crypto::{parse_point, POINT_BYTES},
    NitroDecryptionError,
};

pub(super) const VERSION: u8 = 1;
pub(super) const MAX_CIPHERTEXT: usize = 262_144;
const APP_TYPE: &str = "spr.tvc.decryption_service.v1";
const APP_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Kind {
    ServicePublicKeys,
    ServiceDecrypt,
}

// Serialized structs used as digest inputs list fields in JCS order.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Info {
    executable_digest: String,
    manifest_digest: String,
    max_encrypted_request_bytes: String,
    max_encrypted_response_bytes: String,
    network: NitroNetwork,
    proof_type: String,
    quorum_key_epoch: String,
    quorum_key_id: String,
    quorum_public_key: String,
    release_id: String,
    security_domain_id: String,
    supported_operations: [Kind; 2],
    version: u8,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Boot {
    booted_at_ms: String,
    bootstrap_slots: [u8; 3],
    info: Info,
}

impl Boot {
    fn binding(&self) -> Result<[u8; 32], NitroDecryptionError> {
        Ok(digest(&[b"SPR/native-nitro/discovery/v1", &json(self)?]))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attestation {
    boot: Boot,
    evidence: String,
}

pub(super) struct Replica {
    pub(super) info: Info,
    pub(super) encryption: p256::PublicKey,
    proof_key: VerifyingKey,
    proof_public: String,
    pub(super) valid_from_ms: u64,
    pub(super) valid_through_ms: u64,
}

impl Attestation {
    pub(super) fn verify(
        self,
        trust: &NitroTrust,
        target: &NitroTarget,
        nonce: &[u8; 32],
        now_ms: u64,
    ) -> Result<Replica, NitroDecryptionError> {
        if self.evidence.len() > 2 * 16_384 {
            return Err(NitroDecryptionError::Attestation);
        }
        let boot = self.boot;
        let info = &boot.info;
        let booted_at_ms = boot
            .booted_at_ms
            .parse::<u64>()
            .ok()
            .filter(|time| *time > 0 && time.to_string() == boot.booted_at_ms)
            .ok_or(NitroDecryptionError::Attestation)?;
        let [a, b, c] = boot.bootstrap_slots;
        if ![a, b, c].iter().all(|slot| (1..=6).contains(slot)) || a == b || a == c || b == c {
            return Err(NitroDecryptionError::Attestation);
        }
        let transport = fixed::<{ 2 * POINT_BYTES }>(&info.quorum_public_key)?;
        let release = digest(&[
            b"SPR/native-nitro/release/v1",
            &target.executable_sha256,
            trust.note_seed_commitment(),
            &target.custody_digest,
        ]);
        if info.version != VERSION
            || info.network != trust.network()
            || info.release_id != target.release_id
            || info.security_domain_id != hex::encode(trust.security_domain_id())
            || info.executable_digest != hex::encode(target.executable_sha256)
            || info.manifest_digest != hex::encode(release)
            || info.quorum_key_id != hex::encode(Sha256::digest(transport))
            || info.quorum_key_epoch != target.custody_epoch.to_string()
            || info.proof_type != APP_TYPE
            || info.supported_operations != [Kind::ServicePublicKeys, Kind::ServiceDecrypt]
            || info.max_encrypted_request_bytes != "262144"
            || info.max_encrypted_response_bytes != "262144"
        {
            return Err(NitroDecryptionError::Attestation);
        }

        let (encryption, signing) = transport.split_at(POINT_BYTES);
        let encryption = parse_point(encryption)?;
        parse_point(signing)?;
        let discovery = boot.binding()?;
        let verified = verify_nitro_serving_boot(
            &lower_hex(&self.evidence)?,
            NitroServingPins {
                pcrs: &target.pcrs,
                nonce,
                discovery_binding: &discovery,
            },
            now_ms,
        )
        .map_err(|_| NitroDecryptionError::Attestation)?;
        if booted_at_ms > verified.attested_at_ms {
            return Err(NitroDecryptionError::Attestation);
        }
        Ok(Replica {
            info: boot.info,
            encryption,
            proof_key: VerifyingKey::from_sec1_bytes(&verified.public_keys[POINT_BYTES..])
                .map_err(|_| NitroDecryptionError::Attestation)?,
            proof_public: hex::encode(verified.public_keys),
            valid_from_ms: verified.certificate_valid_from_ms,
            valid_through_ms: verified.certificate_valid_through_ms,
        })
    }
}

#[derive(Serialize)]
pub(super) struct Request<'a> {
    client_response_public_key: String,
    operation: Operation,
    quorum_key_epoch: &'a str,
    quorum_key_id: &'a str,
    request_id: String,
    target_executable_digest: &'a str,
    target_manifest_digest: &'a str,
    target_release_id: &'a str,
    version: u8,
}

impl<'a> Request<'a> {
    pub(super) fn new(
        info: &'a Info,
        id: &[u8; 32],
        response_key: &p256::PublicKey,
        operation: Operation,
    ) -> Self {
        Self {
            client_response_public_key: hex::encode(response_key.to_sec1_point(false).as_bytes()),
            operation,
            quorum_key_epoch: &info.quorum_key_epoch,
            quorum_key_id: &info.quorum_key_id,
            request_id: hex::encode(id),
            target_executable_digest: &info.executable_digest,
            target_manifest_digest: &info.manifest_digest,
            target_release_id: &info.release_id,
            version: VERSION,
        }
    }

    pub(super) fn unsigned_digest(&self) -> Result<[u8; 32], NitroDecryptionError> {
        Ok(digest(&[
            b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1\0",
            &json(self)?,
        ]))
    }

    pub(super) fn set_signature(&mut self, signature_value: &[u8; 64]) {
        if let Operation::Decrypt { signature, .. } = &mut self.operation {
            *signature = Some(hex::encode(signature_value));
        }
    }

    pub(super) fn envelope(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NitroDecryptionError> {
        json(&EncryptedRequest {
            ciphertext: hex::encode(ciphertext),
            quorum_key_epoch: self.quorum_key_epoch,
            quorum_key_id: self.quorum_key_id,
            version: VERSION,
        })
    }

    pub(super) fn verify_response(
        &self,
        replica: &Replica,
        response: EncryptedResponse,
        request_digest: &[u8; 32],
    ) -> Result<Vec<u8>, NitroDecryptionError> {
        let proof = response.tvc_app_proof;
        if response.version != VERSION
            || response.request_id != self.request_id
            || proof.public_key != replica.proof_public
            || proof.scheme != APP_SCHEME
            || response.encrypted_result.len() > MAX_CIPHERTEXT * 2
        {
            return Err(NitroDecryptionError::Protocol);
        }
        let ciphertext = lower_hex(&response.encrypted_result)?;
        let expected = ProofPayload {
            operation: self.operation.kind(),
            request_digest: hex::encode(request_digest),
            request_id: &self.request_id,
            result_digest: hex::encode(digest(&[b"SPR_TVC_RESULT_V1\0", &ciphertext])),
            r#type: APP_TYPE,
            version: VERSION,
        };
        let signature = Signature::from_slice(&fixed::<64>(&proof.signature)?)
            .map_err(|_| NitroDecryptionError::Protocol)?;
        if json(&expected)? != proof.proof_payload.as_bytes()
            || signature.normalize_s() != signature
        {
            return Err(NitroDecryptionError::Protocol);
        }
        replica
            .proof_key
            .verify(proof.proof_payload.as_bytes(), &signature)
            .map_err(|_| NitroDecryptionError::Protocol)?;
        Ok(ciphertext)
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Operation {
    PublicKeys {
        address: String,
        r#type: &'static str,
    },
    Decrypt {
        items: Vec<Item>,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        signer: String,
        r#type: &'static str,
    },
}

impl Operation {
    pub(super) fn public_keys(owner: Pubkey) -> Self {
        Self::PublicKeys {
            address: owner.to_string(),
            r#type: "PublicKeys",
        }
    }

    pub(super) fn decrypt(owner: Pubkey, inputs: &[DecryptRequest<'_>]) -> Self {
        Self::Decrypt {
            items: inputs.iter().map(Item::from).collect(),
            signature: None,
            signer: owner.to_string(),
            r#type: "Decrypt",
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Self::PublicKeys { .. } => Kind::ServicePublicKeys,
            Self::Decrypt { .. } => Kind::ServiceDecrypt,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Item {
    ciphertext: String,
    ephemeral_viewing_public_key: String,
    label: &'static str,
    salt: String,
    slot_index: String,
}

impl From<&DecryptRequest<'_>> for Item {
    fn from(request: &DecryptRequest<'_>) -> Self {
        Self {
            ciphertext: hex::encode(request.ciphertext),
            ephemeral_viewing_public_key: hex::encode(request.tx_viewing_pubkey.as_bytes()),
            label: match request.label {
                DecryptLabel::Utxo => "Transfer",
                DecryptLabel::RingDeposit => "RingDeposit",
            },
            salt: hex::encode(request.salt),
            slot_index: request.slot_index.to_string(),
        }
    }
}

#[derive(Serialize)]
struct EncryptedRequest<'a> {
    ciphertext: String,
    quorum_key_epoch: &'a str,
    quorum_key_id: &'a str,
    version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EncryptedResponse {
    encrypted_result: String,
    request_id: String,
    tvc_app_proof: AppProof,
    version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppProof {
    proof_payload: String,
    public_key: String,
    scheme: String,
    signature: String,
}

#[derive(Serialize)]
struct ProofPayload<'a> {
    operation: Kind,
    request_digest: String,
    request_id: &'a str,
    result_digest: String,
    r#type: &'a str,
    version: u8,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum OperationResult {
    PublicKeys {
        nullifier_public_key: String,
        viewing_public_key: String,
    },
    Decrypt {
        nullifier_secret: SecretHex,
        plaintexts: Vec<SecretHex>,
    },
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(super) struct SecretHex(pub(super) String);

pub(super) fn owner_key(owner: Pubkey) -> Result<OwnerKey, NitroDecryptionError> {
    let key =
        OwnerKey::from_bytes(&owner.to_bytes()).map_err(|_| NitroDecryptionError::InvalidOwner)?;
    if key.is_weak() {
        return Err(NitroDecryptionError::InvalidOwner);
    }
    Ok(key)
}

pub(super) fn owner_message(
    key: &OwnerKey,
    network: NitroNetwork,
    request_digest: &[u8; 32],
) -> Vec<u8> {
    let payload = format!(
        "{DECRYPT_LABEL}/{}/{}",
        network.as_str(),
        hex::encode(request_digest)
    );
    [
        b"\xffsolana offchain\x00".as_slice(),
        Sha256::digest(DECRYPT_LABEL.as_bytes()).as_slice(),
        &[0, 1],
        key.as_bytes(),
        &(payload.len() as u16).to_le_bytes(),
        payload.as_bytes(),
    ]
    .concat()
}

pub(super) fn verify_owner(
    key: &OwnerKey,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), NitroDecryptionError> {
    key.verify_strict(message, &OwnerSignature::from_bytes(signature))
        .map_err(|_| NitroDecryptionError::Signature)
}

pub(super) fn json(value: &impl Serialize) -> Result<Vec<u8>, NitroDecryptionError> {
    serde_json::to_vec(value).map_err(|_| NitroDecryptionError::Protocol)
}

pub(super) fn fixed<const N: usize>(text: &str) -> Result<[u8; N], NitroDecryptionError> {
    let mut bytes = [0; N];
    decode(text, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn lower_hex(text: &str) -> Result<Vec<u8>, NitroDecryptionError> {
    let mut bytes = vec![0; text.len() / 2];
    decode(text, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn decode(text: &str, bytes: &mut [u8]) -> Result<(), NitroDecryptionError> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(NitroDecryptionError::Protocol);
    }
    hex::decode_to_slice(text, bytes).map_err(|_| NitroDecryptionError::Protocol)
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
#[path = "../../tests/nitro_exchange.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "../../tests/nitro_transport.rs"]
mod transport_tests;
