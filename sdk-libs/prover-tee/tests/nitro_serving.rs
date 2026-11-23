use ciborium::Value;
use serde::Deserialize;
use spr_prover_tee::{
    verify_nitro_serving_boot, NitroServingPins, TeeError, VerifiedNitroServingBoot,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    evidence: String,
    nonce: String,
    binding: String,
    pcrs: std::collections::BTreeMap<usize, String>,
    proof_key: String,
    now: String,
}

fn bytes<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

impl Fixture {
    fn load() -> Self {
        // Real evidence from the disposable AWS peer in spr-tvc's SDK suite.
        serde_json::from_str(include_str!("fixtures/aws-nitro-serving.json")).unwrap()
    }

    fn verify(&self, evidence: &[u8], now: u64) -> Result<VerifiedNitroServingBoot, TeeError> {
        let pcrs = std::array::from_fn(|index| bytes(&self.pcrs[&index]));
        verify_nitro_serving_boot(
            evidence,
            NitroServingPins {
                pcrs: &pcrs,
                nonce: &bytes(&self.nonce),
                discovery_binding: &bytes(&self.binding),
            },
            now,
        )
    }

    fn now(&self) -> u64 {
        self.now.parse().unwrap()
    }

    fn evidence(&self) -> Vec<u8> {
        hex::decode(&self.evidence).unwrap()
    }
}

#[test]
fn real_serving_evidence_matches_the_typescript_vector() {
    let fixture = Fixture::load();
    let boot = fixture.verify(&fixture.evidence(), fixture.now()).unwrap();
    assert_eq!(boot.public_keys, bytes(&fixture.proof_key));
    assert_eq!(boot.attested_at_ms, 1_795_290_719_965);
    assert_eq!(boot.certificate_valid_from_ms, 1_795_290_641_001);
    assert_eq!(boot.certificate_valid_through_ms, 1_795_301_443_999);
}

#[test]
fn refuses_a_different_host_image_challenge_or_discovery() {
    let mut fixture = Fixture::load();
    let evidence = fixture.evidence();
    for index in 0..5 {
        let wrong = fixture.pcrs.insert(index, "12".repeat(48)).unwrap();
        assert!(matches!(
            fixture.verify(&evidence, fixture.now()),
            Err(TeeError::NitroDocument(reason)) if reason.contains(&format!("PCR{index}"))
        ));
        fixture.pcrs.insert(index, wrong);
    }
    let nonce = std::mem::replace(&mut fixture.nonce, "22".repeat(32));
    assert!(fixture.verify(&evidence, fixture.now()).is_err());
    fixture.nonce = nonce;
    fixture.binding = "33".repeat(32);
    assert!(fixture.verify(&evidence, fixture.now()).is_err());
}

#[test]
fn enforces_the_certificate_and_freshness_boundaries() {
    let fixture = Fixture::load();
    let evidence = fixture.evidence();
    let boot = fixture.verify(&evidence, fixture.now()).unwrap();
    for now in [
        boot.certificate_valid_from_ms - 1,
        boot.certificate_valid_through_ms + 1,
    ] {
        assert!(matches!(
            fixture.verify(&evidence, now),
            Err(TeeError::NitroDocument(reason)) if reason.contains("certificate")
        ));
    }
    for now in [boot.attested_at_ms - 60_001, boot.attested_at_ms + 60_001] {
        assert!(matches!(
            fixture.verify(&evidence, now),
            Err(TeeError::NitroDocument(reason)) if reason.contains("freshness")
        ));
    }
}

#[test]
fn refuses_even_empty_extra_cose_fields() {
    let fixture = Fixture::load();
    let mut raw: Value = ciborium::from_reader(fixture.evidence().as_slice()).unwrap();
    let cose = match &mut raw {
        Value::Tag(18, value) => value.as_array_mut().unwrap(),
        value => value.as_array_mut().unwrap(),
    };
    // Header decoders can normalize an explicitly empty key ID. Native
    // serving evidence requires the original unprotected map to be empty.
    cose[1] = Value::Map(vec![(Value::Integer(4.into()), Value::Bytes(vec![]))]);
    let mut evidence = Vec::new();
    ciborium::into_writer(&raw, &mut evidence).unwrap();
    assert!(matches!(
        fixture.verify(&evidence, fixture.now()),
        Err(TeeError::NitroDocument(reason)) if reason.contains("unexpected COSE headers")
    ));
}

#[test]
fn rejects_an_oversized_or_tampered_document() {
    let fixture = Fixture::load();
    let mut evidence = fixture.evidence();
    *evidence.last_mut().unwrap() ^= 1;
    assert!(fixture.verify(&evidence, fixture.now()).is_err());
    assert!(fixture.verify(&vec![0; 16_385], fixture.now()).is_err());
}
