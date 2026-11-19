//! What the catalog exercises, derived from the vectors themselves.
//!
//! Each vector maps to the dimension values its steps show. The exported
//! `coverage` object lists, per value, the vectors that exercise it, and
//! [`DEFAULT_RING_VALUES`] and [`CUSTOM_RING_VALUES`] are the values the
//! catalog must exercise in each ring.

use std::collections::{BTreeMap, BTreeSet};

use super::types::{
    Asset, Authorization, Direction, FunctionalVector, InputSlot, Padding, Role, Step,
};

/// Values every ring must settle.
pub const DEFAULT_RING_VALUES: &[&str] = &[
    "input.utxo",
    "input.address",
    "input.cached",
    "input.authorization.hidden",
    "input.authorization.signer",
    "input.hidden_first",
    "input.hidden_not_first",
    "signers.none",
    "signers.one",
    "signers.several",
    "signers.without_input",
    "signers.fee_payer",
    "padding.dummy",
    "padding.compact",
    "padding.extra_input_slots",
    "padding.extra_output_slots",
    "output.owner.hidden",
    "output.owner.signer",
    "output.owner.recipient",
    "output.zero_amount",
    "output.data_hash",
    "public.none",
    "public.deposit",
    "public.withdrawal",
    "public.deposit_and_withdrawal",
    "public.asset.sol",
    "public.asset.spl",
    "public.asset.token_2022",
    "public.assets.1",
    "public.assets.2",
    "public.assets.3",
    "assets.1",
    "assets.2",
    "assets.3",
    "trees.one_input_tree",
    "trees.two_input_trees",
    "trees.output_tree_differs",
    "steps.one",
    "steps.several",
    "hidden_owner.recipient",
    "inputs.24_or_more",
    "outputs.8_or_more",
];

/// Values only a custom ring has: ring and default-ring notes side by side.
pub const CUSTOM_RING_VALUES: &[&str] = &[
    "input.default_ring_note",
    "output.default_ring_note",
    "input.ring_and_default_mixed",
];

/// Dimension value -> names of the vectors that exercise it.
pub fn coverage(vectors: &[FunctionalVector]) -> BTreeMap<String, Vec<String>> {
    let mut coverage: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for vector in vectors {
        for value in values(vector) {
            coverage.entry(value).or_default().push(vector.name.clone());
        }
    }
    coverage
}

/// The dimension values one vector exercises.
pub fn values(vector: &FunctionalVector) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let mut add = |value: &str| {
        values.insert(value.to_string());
    };
    add(if vector.steps.len() > 1 {
        "steps.several"
    } else {
        "steps.one"
    });
    // Every note's ring flag and tree, by id.
    let mut notes: BTreeMap<&str, NoteInfo> = vector
        .funding
        .iter()
        .map(|funded| {
            (
                funded.id.as_str(),
                NoteInfo {
                    ring: funded.ring,
                    tree: funded.tree,
                },
            )
        })
        .collect();
    for step in &vector.steps {
        for output in &step.outputs {
            notes.insert(
                output.id.as_str(),
                NoteInfo {
                    ring: output.ring,
                    tree: step.output_tree,
                },
            );
        }
    }
    for step in &vector.steps {
        step_values(step, &notes, &mut add);
    }
    values
}

#[derive(Clone, Copy)]
struct NoteInfo {
    ring: bool,
    tree: u8,
}

fn step_values(step: &Step, notes: &BTreeMap<&str, NoteInfo>, add: &mut dyn FnMut(&str)) {
    if step.hidden_owner != Role::Hidden {
        add("hidden_owner.recipient");
    }

    // Inputs.
    let mut input_rings = BTreeSet::new();
    let mut input_trees = BTreeSet::new();
    for (position, slot) in step.inputs.iter().enumerate() {
        match slot {
            InputSlot::Utxo { note, cached, .. } => {
                add("input.utxo");
                if *cached {
                    add("input.cached");
                }
                if let Some(info) = notes.get(note.as_str()) {
                    input_rings.insert(info.ring);
                    input_trees.insert(info.tree);
                    if !info.ring {
                        add("input.default_ring_note");
                    }
                }
            }
            InputSlot::Address { tree, .. } => {
                add("input.address");
                input_trees.insert(*tree);
            }
        }
        match slot.authorization() {
            Authorization::Hidden => {
                add("input.authorization.hidden");
                if position == 0 {
                    add("input.hidden_first");
                } else {
                    add("input.hidden_not_first");
                }
            }
            Authorization::Signer => add("input.authorization.signer"),
        }
    }
    if input_rings.len() > 1 {
        add("input.ring_and_default_mixed");
    }
    add(if input_trees.len() > 1 {
        "trees.two_input_trees"
    } else {
        "trees.one_input_tree"
    });
    if step.inputs.len() >= 24 {
        add("inputs.24_or_more");
    }

    // Signers.
    add(match step.signers.len() {
        0 => "signers.none",
        1 => "signers.one",
        _ => "signers.several",
    });
    for signer in &step.signers {
        if !step.inputs.iter().any(|slot| slot.owner() == *signer) {
            add("signers.without_input");
        }
        if *signer == step.fee_payer {
            add("signers.fee_payer");
        }
    }

    // Padding.
    add(match step.padding {
        Padding::Dummy => "padding.dummy",
        Padding::Compact => "padding.compact",
    });
    if usize::from(step.min_input_slots) > step.inputs.len() {
        add("padding.extra_input_slots");
    }
    if usize::from(step.min_output_slots) > step.outputs.len() {
        add("padding.extra_output_slots");
    }

    // Outputs.
    let mut assets = BTreeSet::new();
    for output in &step.outputs {
        assets.insert(output.asset);
        add(if output.owner == step.hidden_owner {
            "output.owner.hidden"
        } else if step.signers.contains(&output.owner) {
            "output.owner.signer"
        } else {
            "output.owner.recipient"
        });
        if output.amount == 0 {
            add("output.zero_amount");
        }
        if output.data_hash.is_some() {
            add("output.data_hash");
        }
        if !output.ring {
            add("output.default_ring_note");
        }
    }
    if step.outputs.len() >= 8 {
        add("outputs.8_or_more");
    }
    if step.output_tree != 0 {
        add("trees.output_tree_differs");
    }

    // Public legs.
    let deposits = step
        .public
        .iter()
        .any(|leg| leg.direction == Direction::Deposit);
    let withdrawals = step
        .public
        .iter()
        .any(|leg| leg.direction == Direction::Withdrawal);
    add(match (deposits, withdrawals) {
        (false, false) => "public.none",
        (true, false) => "public.deposit",
        (false, true) => "public.withdrawal",
        (true, true) => "public.deposit_and_withdrawal",
    });
    let public_assets: BTreeSet<Asset> = step.public.iter().map(|leg| leg.asset).collect();
    for asset in &public_assets {
        assets.insert(*asset);
        add(match asset {
            Asset::Sol => "public.asset.sol",
            Asset::SplA | Asset::SplB => "public.asset.spl",
            Asset::Token2022A => "public.asset.token_2022",
        });
    }
    match public_assets.len() {
        1 => add("public.assets.1"),
        2 => add("public.assets.2"),
        3 => add("public.assets.3"),
        _ => {}
    }
    match assets.len() {
        1 => add("assets.1"),
        2 => add("assets.2"),
        3 => add("assets.3"),
        _ => {}
    }
}
