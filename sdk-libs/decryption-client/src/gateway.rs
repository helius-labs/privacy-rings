use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use qos_nsm::nitro::{
    attestation_doc_from_der, cert_from_pem, verify_attestation_doc_against_user_input,
    verify_attestation_doc_manifest_commitment, Live, AWS_ROOT_CERT_PEM,
};
use qos_p256::{encrypt::P256EncryptPair, P256Public};
use reqwest::{
    blocking::{Client, Response},
    header::{HeaderMap, HeaderValue},
    Url,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_signer::Signer;
use spr_keypair::{PublicKey, ShieldedAddress, X25519Pubkey};
use spr_transaction::{DecryptLabel as WalletLabel, DecryptRequest};
use spr_tvc_protocol::{
    constants::{
        API_VERSION, MAX_ITEMS_PER_BATCH, SEC1_UNCOMPRESSED_LEN, TVC_APP_PROOF_SCHEME,
        TVC_QOS_PING_PROOF_TYPE,
    },
    crypto::verify_p256_message,
    decryption_service::{
        decrypt_message, service_request_digest, DecryptedOutputs, ServiceOperation,
        ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE,
    },
    digest::result_digest,
    encoding::{jcs_serialize, parse_strict_json},
    verify_signed_release_policy, AppProof, DecryptItem, DecryptLabel, EncryptedRequest,
    EncryptedResponse, Network, OperationProofPayload, PinnedReleaseAuthorities, QosPingChallenge,
    QosPingRequest, QosPingResponse, ServiceInfo, SignedReleasePolicy,
};

const MAX_GATEWAY_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePin {
    release_policy: SignedReleasePolicy,
    release_authorities: PinnedReleaseAuthorities,
    qos_identity_pcrs: Pcrs,
}

impl ReleasePin {
    /// Parses a pin supplied by the application from an independent trusted source.
    pub fn from_json(input: &str) -> Result<Self> {
        parse_strict_json::<Option<Self>>(input)?.context("missing decryption release pin")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pcrs {
    #[serde(rename = "0")]
    pcr0: String,
    #[serde(rename = "1")]
    pcr1: String,
    #[serde(rename = "2")]
    pcr2: String,
    #[serde(rename = "3")]
    pcr3: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootProof {
    aws_attestation_doc_b64: String,
    ephemeral_public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Session {
    info: ServiceInfo,
    ping: QosPingResponse,
    boot_proof: BootProof,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Answer {
    response: EncryptedResponse,
    boot_proof: Option<BootProof>,
}

struct HostedTrust {
    pin: ReleasePin,
    aws_root: Vec<u8>,
}

enum Trust {
    Gatekeeper(Box<HostedTrust>),
    #[cfg(feature = "test-support")]
    Loopback(Vec<u8>),
}

pub struct DecryptionClient {
    http: Client,
    endpoint: Url,
    network: Network,
    info: ServiceInfo,
    quorum: P256Public,
    trust: Trust,
}

impl DecryptionClient {
    /// Connects using release anchors obtained from trusted application configuration.
    pub fn connect(
        mut endpoint: Url,
        api_key: &str,
        network: Network,
        pin: ReleasePin,
    ) -> Result<Self> {
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && !api_key.trim().is_empty(),
            "Gatekeeper requires HTTPS and an API key"
        );
        endpoint.set_path("/");
        verify_signed_release_policy(
            &pin.release_policy,
            &pin.release_authorities,
            network,
            now_ms()?,
        )?;
        let policy = &pin.release_policy.policy;
        let quorum = P256Public::from_bytes(&policy.quorum_public_key)
            .map_err(|error| anyhow!("invalid pinned Quorum key: {error:?}"))?;
        let mut headers = HeaderMap::new();
        let mut api_key = HeaderValue::from_str(api_key).context("invalid Gatekeeper API key")?;
        api_key.set_sensitive(true);
        headers.insert("x-api-key", api_key);
        let http = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let challenge = jcs_serialize(&QosPingChallenge {
            r#type: TVC_QOS_PING_PROOF_TYPE.into(),
            version: API_VERSION,
            challenge: nonce()?,
        })?;
        let session: Session = read(post(
            &http,
            &endpoint,
            "v1/decryption/session",
            &QosPingRequest {
                version: API_VERSION,
                encrypted_challenge: seal(&quorum, challenge.as_bytes())?,
            },
        )?)?;
        let info = session.info;
        ensure!(
            info.version == API_VERSION
                && info.network == policy.network
                && info.release_id == policy.release_id
                && info.security_domain_id == policy.security_domain_id
                && info.quorum_key_id == policy.quorum_key_id
                && info.quorum_key_epoch == policy.quorum_key_epoch
                && info.quorum_public_key == policy.quorum_public_key
                && info.supported_operations == policy.allowed_operations
                && info.proof_type == SERVICE_PROOF_TYPE
                && info.max_encrypted_request_bytes
                    == u64::from(policy.max_encrypted_request_bytes)
                && info.max_encrypted_response_bytes
                    == u64::from(policy.max_encrypted_response_bytes)
                && policy
                    .accepted_manifest_digests
                    .contains(&hex::encode(info.manifest_digest))
                && policy
                    .accepted_executable_digests
                    .contains(&hex::encode(info.executable_digest)),
            "Gatekeeper discovery does not match the signed release"
        );
        let aws_root = cert_from_pem(AWS_ROOT_CERT_PEM)
            .map_err(|error| anyhow!("invalid pinned Nitro root: {error:?}"))?;
        let gateway = Self {
            http,
            endpoint,
            network,
            info,
            quorum,
            trust: Trust::Gatekeeper(Box::new(HostedTrust { pin, aws_root })),
        };
        ensure!(
            session.ping.version == API_VERSION
                && session.ping.tvc_app_proof.proof_payload == challenge,
            "session proof does not bind the challenge"
        );
        gateway.verify_proof(&session.ping.tvc_app_proof, Some(&session.boot_proof))?;
        Ok(gateway)
    }

    /// Connects to a loopback test enclave using the shared public fixture.
    #[cfg(feature = "test-support")]
    pub fn connect_local(endpoint: Url) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fixture {
            version: u8,
            release_id: String,
            quorum_key_id: String,
            security_domain_label: String,
            manifest_label: String,
            executable_label: String,
            quorum_public_key: String,
            ephemeral_public_key: String,
            operations: Vec<spr_tvc_protocol::OperationKind>,
        }

        use spr_tvc_protocol::constants::{
            MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES,
        };
        use spr_tvc_protocol::digest::sha256;
        ensure!(
            endpoint.scheme() == "http"
                && endpoint.host_str().is_some_and(|host| {
                    host.trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                })
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/",
            "test enclave endpoint must be a loopback HTTP origin"
        );
        let fixture: Fixture = parse_strict_json(include_str!(
            "../../../services/decryption-service/tests/fixtures/local-testkit.json"
        ))?;
        ensure!(fixture.version == 1, "unsupported loopback fixture");
        let quorum_public_key = hex::decode(fixture.quorum_public_key)?;
        let quorum = P256Public::from_bytes(&quorum_public_key)
            .map_err(|error| anyhow!("invalid loopback Quorum key: {error:?}"))?;
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let challenge = jcs_serialize(&QosPingChallenge {
            r#type: TVC_QOS_PING_PROOF_TYPE.into(),
            version: API_VERSION,
            challenge: nonce()?,
        })?;
        let info: ServiceInfo = read(http.get(endpoint.join("v1/info")?).send()?)?;
        let expected = ServiceInfo {
            version: API_VERSION,
            network: Network::Devnet,
            security_domain_id: sha256(fixture.security_domain_label.as_bytes()),
            release_id: fixture.release_id,
            manifest_digest: sha256(fixture.manifest_label.as_bytes()),
            executable_digest: sha256(fixture.executable_label.as_bytes()),
            quorum_public_key,
            quorum_key_id: fixture.quorum_key_id,
            quorum_key_epoch: 1,
            supported_operations: fixture.operations,
            max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES,
            max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES,
            proof_type: SERVICE_PROOF_TYPE.into(),
        };
        ensure!(
            info == expected,
            "loopback enclave does not match the test fixture"
        );
        let ping: QosPingResponse = read(post(
            &http,
            &endpoint,
            "v1/ping",
            &QosPingRequest {
                version: API_VERSION,
                encrypted_challenge: seal(&quorum, challenge.as_bytes())?,
            },
        )?)?;
        let client = Self {
            http,
            endpoint,
            network: info.network,
            info,
            quorum,
            trust: Trust::Loopback(hex::decode(fixture.ephemeral_public_key)?),
        };
        ensure!(
            ping.version == API_VERSION && ping.tvc_app_proof.proof_payload == challenge,
            "loopback ping does not bind the challenge"
        );
        client.verify_proof(&ping.tvc_app_proof, None)?;
        Ok(client)
    }

    pub fn public_keys(&self, owner: spr_transaction::Address) -> Result<ShieldedAddress> {
        let result = self.call(
            ServiceOperation::PublicKeys {
                address: owner.to_string(),
            },
            None,
        )?;
        let ServiceResult::PublicKeys {
            viewing_public_key,
            nullifier_public_key,
        } = result
        else {
            anyhow::bail!("expected PublicKeys");
        };
        Ok(ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(&owner.to_bytes()),
            viewing_pubkey: X25519Pubkey::from_bytes(viewing_public_key)?,
            nullifier_pubkey: nullifier_public_key,
        })
    }

    pub(crate) fn decrypt(
        &self,
        owner: &dyn Signer,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs> {
        let len = items.len();
        ensure!(
            len <= MAX_ITEMS_PER_BATCH as usize,
            "too many decrypt items"
        );
        let result = self.call(decrypt_operation(owner.try_pubkey()?, items), Some(owner))?;
        let ServiceResult::Decrypt(outputs) = result else {
            anyhow::bail!("expected Decrypt");
        };
        ensure!(
            outputs.plaintexts.len() == len,
            "one plaintext per requested item"
        );
        Ok(outputs)
    }

    #[cfg(feature = "test-support")]
    pub fn check_authorization(
        &self,
        owner: &dyn Signer,
        other: &dyn Signer,
        item: &DecryptItem,
    ) -> Result<()> {
        for (name, signer) in [("unsigned", None), ("wrong owner", Some(other))] {
            let (request, _) = self.prepare(
                decrypt_operation(owner.try_pubkey()?, vec![item.clone()]),
                signer,
            )?;
            self.expect_invalid(&request)
                .with_context(|| format!("{name} decrypt"))?;
        }
        let (mut request, _) = self.prepare(
            decrypt_operation(owner.try_pubkey()?, vec![item.clone()]),
            Some(owner),
        )?;
        let ServiceOperation::Decrypt { items, .. } = &mut request.operation else {
            anyhow::bail!("expected a decrypt request");
        };
        items[0].slot_index ^= 1;
        self.expect_invalid(&request)
            .context("mutated signed batch")?;

        let (request, _) = self.prepare(
            decrypt_operation(
                owner.try_pubkey()?,
                vec![item.clone(); MAX_ITEMS_PER_BATCH as usize + 1],
            ),
            Some(owner),
        )?;
        self.expect_invalid(&request)
            .context("oversized decrypt batch")
    }

    #[cfg(feature = "test-support")]
    pub fn check_replay(&self, owner: &dyn Signer, item: DecryptItem) -> Result<DecryptedOutputs> {
        let (request, response_key) = self.prepare(
            decrypt_operation(owner.try_pubkey()?, vec![item]),
            Some(owner),
        )?;
        let envelope = self.seal_request(&request)?;
        let first: Answer = read(self.send(&envelope)?)?;
        let again: Answer = read(self.send(&envelope)?)?;
        ensure!(
            first.response == again.response,
            "replay returned a different encrypted result"
        );
        self.verify_proof(&again.response.tvc_app_proof, again.boot_proof.as_ref())?;
        let ServiceResult::Decrypt(outputs) = self.open_answer(&request, response_key, first)?
        else {
            anyhow::bail!("expected Decrypt");
        };
        ensure!(
            outputs.plaintexts.len() == 1,
            "replay must return the one requested plaintext"
        );
        Ok(outputs)
    }

    #[cfg(feature = "test-support")]
    fn expect_invalid(&self, request: &ServiceRequest) -> Result<()> {
        let response = self.send(&self.seal_request(request)?)?;
        ensure!(
            response.status() == reqwest::StatusCode::BAD_REQUEST,
            "expected decryption rejection, got {}",
            response.status()
        );
        let error: serde_json::Value = read_body(response)?;
        ensure!(
            error == serde_json::json!({"error": "InvalidRequest"}),
            "expected enclave rejection"
        );
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub fn test_decrypt(
        &self,
        owner: &dyn Signer,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs> {
        self.decrypt(owner, items)
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn Signer>,
    ) -> Result<ServiceResult> {
        let (request, response_key) = self.prepare(operation, signer)?;
        let response = self.send(&self.seal_request(&request)?)?;
        let answer = match &self.trust {
            Trust::Gatekeeper(_) => read(response)?,
            #[cfg(feature = "test-support")]
            Trust::Loopback(_) => Answer {
                response: read(response)?,
                boot_proof: None,
            },
        };
        self.open_answer(&request, response_key, answer)
    }

    fn open_answer(
        &self,
        request: &ServiceRequest,
        response_key: P256EncryptPair,
        answer: Answer,
    ) -> Result<ServiceResult> {
        let Answer {
            response,
            boot_proof,
        } = answer;
        ensure!(
            response.encrypted_result.len() as u64 <= self.info.max_encrypted_response_bytes,
            "decryption result exceeds the signed release limit"
        );
        let expected = OperationProofPayload {
            r#type: SERVICE_PROOF_TYPE.into(),
            version: API_VERSION,
            request_id: request.request_id,
            request_digest: service_request_digest(request)?,
            result_digest: result_digest(&response.encrypted_result),
            operation: request.operation.kind(),
        };
        ensure!(
            response.version == API_VERSION
                && response.request_id == request.request_id
                && response.tvc_app_proof.proof_payload == jcs_serialize(&expected)?,
            "response proof does not match the request"
        );
        self.verify_proof(&response.tvc_app_proof, boot_proof.as_ref())?;
        #[cfg(feature = "test-support")]
        ensure!(
            P256EncryptPair::generate()
                .decrypt(&response.encrypted_result)
                .is_err(),
            "an unrelated response key opened the result"
        );
        let plaintext = response_key
            .decrypt(&response.encrypted_result)
            .map_err(|error| anyhow!("response encryption verification failed: {error:?}"))?;
        Ok(parse_strict_json(std::str::from_utf8(&plaintext)?)?)
    }

    fn prepare(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn Signer>,
    ) -> Result<(ServiceRequest, P256EncryptPair)> {
        let response_key = P256EncryptPair::generate();
        let mut request = ServiceRequest {
            version: API_VERSION,
            request_id: nonce()?,
            target_release_id: self.info.release_id.clone(),
            target_manifest_digest: self.info.manifest_digest,
            target_executable_digest: self.info.executable_digest,
            quorum_key_id: self.info.quorum_key_id.clone(),
            quorum_key_epoch: self.info.quorum_key_epoch,
            client_response_public_key: response_key.public_key().to_bytes().to_vec(),
            operation,
        };
        let digest = service_request_digest(&request)?;
        if signer.is_some() {
            self.check_release()?;
            self.seal_request(&request)?;
        }
        if let (
            Some(signing_key),
            ServiceOperation::Decrypt {
                signer, signature, ..
            },
        ) = (signer, &mut request.operation)
        {
            let address: spr_transaction::Address = signer.parse()?;
            *signature = signing_key
                .try_sign_message(&decrypt_message(&address.to_bytes(), self.network, &digest))?
                .into();
        }
        Ok((request, response_key))
    }

    fn seal_request(&self, request: &ServiceRequest) -> Result<EncryptedRequest> {
        let wrapped = EncryptedRequest {
            version: API_VERSION,
            quorum_key_id: self.info.quorum_key_id.clone(),
            quorum_key_epoch: self.info.quorum_key_epoch,
            ciphertext: seal(&self.quorum, jcs_serialize(request)?.as_bytes())?,
        };
        ensure!(
            jcs_serialize(&wrapped)?.len() as u64 <= self.info.max_encrypted_request_bytes,
            "decryption request exceeds the signed release limit"
        );
        Ok(wrapped)
    }

    fn send(&self, request: &EncryptedRequest) -> Result<Response> {
        self.check_release()?;
        let path = match &self.trust {
            Trust::Gatekeeper(_) => "v1/decryption/operations",
            #[cfg(feature = "test-support")]
            Trust::Loopback(_) => "v1/operations",
        };
        post(&self.http, &self.endpoint, path, request)
    }

    fn check_release(&self) -> Result<()> {
        match &self.trust {
            Trust::Gatekeeper(trust) => verify_signed_release_policy(
                &trust.pin.release_policy,
                &trust.pin.release_authorities,
                self.network,
                now_ms()?,
            )?,
            #[cfg(feature = "test-support")]
            Trust::Loopback(_) => (),
        }
        Ok(())
    }

    fn verify_proof(&self, app: &AppProof, boot: Option<&BootProof>) -> Result<()> {
        ensure!(
            app.scheme == TVC_APP_PROOF_SCHEME && app.public_key.len() == 2 * SEC1_UNCOMPRESSED_LEN,
            "unexpected App Proof scheme or key"
        );
        verify_p256_message(
            &app.public_key[SEC1_UNCOMPRESSED_LEN..],
            app.proof_payload.as_bytes(),
            &app.signature,
        )?;
        let trust = match &self.trust {
            Trust::Gatekeeper(trust) => trust,
            #[cfg(feature = "test-support")]
            Trust::Loopback(expected) => {
                ensure!(
                    app.public_key == *expected,
                    "unexpected loopback signing key"
                );
                return Ok(());
            }
        };
        let boot = boot.context("Gatekeeper omitted the replica Boot Proof")?;
        let boot_key =
            spr_tvc_protocol::encoding::decode_lower_hex(&boot.ephemeral_public_key_hex)?;
        let now = now_ms()?;
        let doc = attestation_doc_from_der(
            &STANDARD.decode(&boot.aws_attestation_doc_b64)?,
            &trust.aws_root,
            now / 1000,
        )
        .map_err(|error| anyhow!("Nitro Boot Proof chain: {error:?}"))?;
        ensure!(
            doc.timestamp > 0 && doc.timestamp <= now + 60_000,
            "Boot Proof timestamp is invalid"
        );
        ensure!(
            doc.public_key.as_ref().map(|key| key.as_slice()) == Some(app.public_key.as_slice())
                && boot_key == app.public_key,
            "Boot Proof belongs to another replica"
        );
        let pcrs = &trust.pin.qos_identity_pcrs;
        verify_attestation_doc_against_user_input(
            &doc,
            &self.info.manifest_digest,
            &hex::decode(&pcrs.pcr0)?,
            &hex::decode(&pcrs.pcr1)?,
            &hex::decode(&pcrs.pcr2)?,
            &hex::decode(&pcrs.pcr3)?,
        )
        .map_err(|error| anyhow!("Boot Proof manifest and PCR0..3: {error:?}"))?;
        verify_attestation_doc_manifest_commitment::<Live>(&doc, &self.info.manifest_digest)
            .map_err(|error| anyhow!("Boot Proof PCR17 commitment: {error:?}"))
    }
}

fn decrypt_operation(owner: solana_address::Address, items: Vec<DecryptItem>) -> ServiceOperation {
    ServiceOperation::Decrypt {
        signer: owner.to_string(),
        signature: [0; 64],
        items,
    }
}

pub(crate) fn decrypt_item(request: &DecryptRequest<'_>) -> DecryptItem {
    DecryptItem {
        ciphertext: request.ciphertext.to_vec(),
        ephemeral_viewing_public_key: request.tx_viewing_pubkey.as_bytes().to_vec(),
        salt: request.salt.to_vec(),
        slot_index: request.slot_index.into(),
        label: match request.label {
            WalletLabel::Utxo => DecryptLabel::Transfer,
            WalletLabel::RingDeposit => DecryptLabel::RingDeposit,
        },
    }
}

fn seal(quorum: &P256Public, plaintext: &[u8]) -> Result<Vec<u8>> {
    quorum
        .encrypt(plaintext)
        .map_err(|error| anyhow!("seal request: {error:?}"))
}

fn post(http: &Client, endpoint: &Url, route: &str, body: &impl Serialize) -> Result<Response> {
    http.post(endpoint.join(route)?)
        .json(body)
        .send()
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("Gatekeeper {route}"))
}

fn read<T: DeserializeOwned>(response: Response) -> Result<T> {
    read_body(
        response
            .error_for_status()
            .map_err(reqwest::Error::without_url)?,
    )
}

fn read_body<T: DeserializeOwned>(response: Response) -> Result<T> {
    let mut body = Vec::new();
    response
        .take(MAX_GATEWAY_BYTES + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() as u64 <= MAX_GATEWAY_BYTES,
        "Gatekeeper response too large"
    );
    Ok(parse_strict_json(std::str::from_utf8(&body)?)?)
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn nonce() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|error| anyhow!("system randomness: {error}"))?;
    Ok(bytes)
}
