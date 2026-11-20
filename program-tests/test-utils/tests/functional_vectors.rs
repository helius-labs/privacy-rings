//! The functional transact catalog: generator checks and the committed file.

use std::collections::BTreeSet;

use serde_json::Value;
use spr_test_utils::functional_vectors::{
    committed_file, compute_file,
    coverage::{values, CUSTOM_RING_VALUES, DEFAULT_RING_VALUES},
    spec::{note, pay, run, spend, StepSpec, VectorSpec},
    write_committed_file, Asset, Authorization, Direction, FunctionalVector, InputSlot, Padding,
    RingStatus, Role, Step,
};

const CIRCUIT_VECTORS: &str = include_str!("../../../test-vectors/anonymous_eddsa_accepting.json");

/// Every dimension value has a case each ring runs, or a named pending case.
#[test]
fn the_catalog_covers_every_dimension_value() {
    let vectors = compute_file().unwrap().vectors;
    let observed: BTreeSet<String> = vectors.iter().flat_map(values).collect();
    let known: BTreeSet<String> = DEFAULT_RING_VALUES
        .iter()
        .chain(CUSTOM_RING_VALUES)
        .map(|value| value.to_string())
        .collect();
    let unlisted: Vec<_> = observed.difference(&known).collect();
    assert!(
        unlisted.is_empty(),
        "values without a ring list: {unlisted:?}"
    );

    let covered = |value: &str, status: fn(&FunctionalVector) -> &RingStatus| {
        vectors
            .iter()
            .filter(|vector| values(vector).contains(value))
            .any(|vector| !matches!(status(vector), RingStatus::NotApplicable { .. }))
    };
    let missing_default: Vec<_> = DEFAULT_RING_VALUES
        .iter()
        .filter(|value| !covered(value, |vector| &vector.rings.default))
        .collect();
    let missing_custom: Vec<_> = DEFAULT_RING_VALUES
        .iter()
        .chain(CUSTOM_RING_VALUES)
        .filter(|value| !covered(value, |vector| &vector.rings.custom))
        .collect();
    assert_eq!(
        (missing_default, missing_custom),
        (Vec::new(), Vec::new()),
        "values no case exercises (default ring, custom ring)"
    );
}

/// A case linked to a circuit vector has the same real slots, amounts,
/// padding, slot counts and public movement.
#[test]
fn every_case_names_an_existing_circuit_vector() {
    let circuit: Value = serde_json::from_str(CIRCUIT_VECTORS).unwrap();
    let circuit_vectors = circuit["vectors"].as_array().unwrap();
    for vector in compute_file().unwrap().vectors {
        let Some(name) = &vector.circuit_vector else {
            continue;
        };
        let scenario = &circuit_vectors
            .iter()
            .find(|candidate| candidate["name"] == name.as_str())
            .unwrap_or_else(|| panic!("{}: no circuit vector {name}", vector.name))["scenario"];
        assert_eq!(
            vector.steps.len(),
            1,
            "{}: a linked case has one step",
            vector.name
        );
        let step = vector.steps.first().unwrap();
        assert_eq!(
            CircuitPattern::of_functional(&vector, step),
            CircuitPattern::of_circuit(scenario),
            "{} against circuit vector {name}",
            vector.name
        );
    }
}

#[derive(Debug, PartialEq)]
struct CircuitPattern {
    /// (kind, owner class, ring, amount); an address carries no ring flag.
    inputs: Vec<(String, String, Option<bool>, String)>,
    /// (owner class, ring, amount, carries data)
    outputs: Vec<(String, bool, String, bool)>,
    /// The padding mode, when any slot is padding.
    padding: Option<String>,
    slots: (u64, u64),
    /// Signed public amounts, sorted.
    public: Vec<i128>,
}

impl CircuitPattern {
    fn of_functional(vector: &FunctionalVector, step: &Step) -> Self {
        let class = |role: Role| {
            if role == step.hidden_owner {
                "hidden"
            } else if step.signers.contains(&role) {
                "signer"
            } else {
                "recipient"
            }
            .to_string()
        };
        let inputs = step
            .inputs
            .iter()
            .map(|slot| match slot {
                InputSlot::Utxo {
                    note,
                    owner,
                    authorization,
                    ..
                } => {
                    let funded = vector
                        .funding
                        .iter()
                        .find(|funded| &funded.id == note)
                        .unwrap();
                    let owner_class = match authorization {
                        Authorization::Hidden => "hidden".to_string(),
                        Authorization::Signer => class(*owner),
                    };
                    (
                        "utxo".to_string(),
                        owner_class,
                        Some(funded.ring),
                        funded.amount.to_string(),
                    )
                }
                InputSlot::Address { owner, .. } => {
                    ("address".to_string(), class(*owner), None, "0".to_string())
                }
            })
            .collect();
        let outputs = step
            .outputs
            .iter()
            .map(|output| {
                (
                    class(output.owner),
                    output.ring,
                    output.amount.to_string(),
                    output.data_hash.is_some(),
                )
            })
            .collect();
        let padded = usize::from(step.min_input_slots) > step.inputs.len()
            || usize::from(step.min_output_slots) > step.outputs.len();
        let mut public: Vec<i128> = step
            .public
            .iter()
            .map(|leg| match leg.direction {
                Direction::Deposit => i128::from(leg.amount),
                Direction::Withdrawal => -i128::from(leg.amount),
            })
            .collect();
        public.sort();
        Self {
            inputs,
            outputs,
            padding: padded.then(|| {
                match step.padding {
                    Padding::Dummy => "dummy",
                    Padding::Compact => "compact",
                }
                .to_string()
            }),
            slots: (
                u64::from(step.min_input_slots),
                u64::from(step.min_output_slots),
            ),
            public,
        }
    }

    fn of_circuit(scenario: &Value) -> Self {
        let text = |value: &Value| value.as_str().unwrap().to_string();
        let slots = |key: &str| scenario[key].as_array().unwrap().clone();
        let mut padding = None;
        let mut inputs = Vec::new();
        for slot in slots("inputs") {
            match slot["kind"].as_str().unwrap() {
                kind @ ("utxo" | "address") => inputs.push((
                    kind.to_string(),
                    text(&slot["owner"]),
                    (kind == "utxo").then(|| slot["ring"].as_bool().unwrap()),
                    text(&slot["amount"]),
                )),
                kind => padding = Some(kind.to_string()),
            }
        }
        let zero = format!("0x{}", "0".repeat(64));
        let mut outputs = Vec::new();
        for slot in slots("outputs") {
            match slot["kind"].as_str().unwrap() {
                "utxo" => outputs.push((
                    text(&slot["owner"]),
                    slot["ring"].as_bool().unwrap(),
                    text(&slot["amount"]),
                    text(&slot["dataHash"]) != zero,
                )),
                kind => padding = Some(kind.to_string()),
            }
        }
        let mut public: Vec<i128> = slots("public")
            .iter()
            .map(|leg| text(&leg["amount"]).parse().unwrap())
            .filter(|amount| *amount != 0)
            .collect();
        public.sort();
        Self {
            inputs,
            outputs,
            padding,
            slots: (
                scenario["nInputs"].as_u64().unwrap(),
                scenario["nOutputs"].as_u64().unwrap(),
            ),
            public,
        }
    }
}

#[test]
fn committed_functional_vectors_match() {
    assert_eq!(committed_file().unwrap(), compute_file().unwrap());
}

#[test]
#[ignore = "rewrites test-vectors/transact_functional.json"]
fn write_functional_vectors() {
    write_committed_file(&compute_file().unwrap()).unwrap();
}

fn mixed_owner_spec(change: u64) -> VectorSpec {
    VectorSpec {
        name: "spec_check",
        description: "a hidden note beside a signer's note",
        circuit_vector: None,
        default_ring: run(),
        custom_ring: run(),
        funding: vec![
            note("h0", Role::Hidden, Asset::Sol, 100),
            note("s0", Role::Signer(0), Asset::Sol, 50),
        ],
        steps: vec![StepSpec::new(
            vec![spend("h0"), spend("s0")],
            vec![
                pay("r0", Role::Recipient(0), Asset::Sol, 120),
                pay("c0", Role::Hidden, Asset::Sol, change),
            ],
        )
        .signers(&[Role::Signer(0)])],
    }
}

#[test]
fn spec_refuses_an_unbalanced_case() {
    let error = mixed_owner_spec(31).build().unwrap_err();
    assert!(
        format!("{error:#}").contains("SOL does not balance: 150 in, 151 out"),
        "{error:#}"
    );
}

#[test]
fn spec_refuses_an_unlisted_input_owner() {
    let mut spec = mixed_owner_spec(30);
    for step in &mut spec.steps {
        step.signers.clear();
    }
    let error = spec.build().unwrap_err();
    assert!(
        format!("{error:#}").contains(
            "input 1 is owned by signer0, who is neither the hidden owner nor a listed signer"
        ),
        "{error:#}"
    );
}

#[test]
fn spec_derives_the_expectations() {
    let vector = mixed_owner_spec(30).build().unwrap();
    let step = vector.steps.first().unwrap();
    assert_eq!(
        step.expect.transaction_signers,
        [Role::Payer, Role::Signer(0)]
    );
    assert_eq!(step.expect.absent_signers, [Role::Hidden]);
    assert_eq!(step.expect.real_inputs, 2);
    assert_eq!(step.expect.real_outputs, 2);
    let unspent: Vec<_> = vector
        .unspent_after
        .iter()
        .map(|(role, notes)| {
            (
                *role,
                notes.iter().map(|note| note.amount).collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        unspent,
        [
            (Role::Hidden, vec![30]),
            (Role::Signer(0), vec![]),
            (Role::Recipient(0), vec![120]),
        ]
    );
}
