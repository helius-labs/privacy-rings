//! The functional transact catalog.
//!
//! A case linked to a circuit vector keeps that vector's real slots and
//! amounts, so the two catalogs describe the same transaction at two layers.

use anyhow::Result;

use super::{
    spec::{
        address, deposit, not_applicable, note, pay, pending, run, spend, spend_cached, withdraw,
        StepSpec, VectorSpec,
    },
    Asset::{Sol, SplA, SplB, Token2022A},
    FunctionalVector, FundedNote, RingStatus,
    Role::{Funder, Hidden, Payer, Recipient, Signer},
};

/// The custom ring's hidden owner must own the first input.
const HIDDEN_FIRST: &str =
    "the anonymous ring circuit requires the first input to be the hidden owner's note";
/// `Submission` takes the owner signers from the inputs it spends.
const SIGNERS_FROM_INPUTS: &str = "the client derives the owner signers from the spent inputs, so a signer without an input needs a hand-built transact";
/// `ConfidentialTransaction::new_with_addresses` places addresses before notes.
const ADDRESSES_FIRST: &str =
    "the client places address slots before note slots, so a note cannot precede an address";
/// Ring notes and ring data exist only in a custom ring.
const NO_RING_NOTES: &str = "the default ring has no ring notes or ring data";
/// Anonymous custom-ring transfer keys.
const NO_ANONYMOUS_KEY: &str = "no anonymous custom-ring transfer key has this many slots";

pub fn catalog() -> Result<Vec<FunctionalVector>> {
    specs().into_iter().map(VectorSpec::build).collect()
}

fn specs() -> Vec<VectorSpec> {
    let mut specs = Vec::new();
    specs.extend(ownership());
    specs.extend(outputs());
    specs.extend(padding());
    specs.extend(public_value());
    specs.extend(assets());
    specs.extend(addresses());
    specs.extend(data());
    specs.extend(trees());
    specs.extend(shapes());
    specs.extend(ring_boundary());
    specs.extend(multi_step());
    specs
}

/// One hidden note of 100 paying the listed outputs, as most circuit cases do.
fn hidden_spend(name: &'static str, description: &'static str) -> VectorSpec {
    VectorSpec {
        name,
        description,
        circuit_vector: None,
        default_ring: run(),
        custom_ring: run(),
        funding: vec![note("h0", Hidden, Sol, 100)],
        steps: Vec::new(),
    }
}

impl VectorSpec {
    fn linked(mut self) -> Self {
        self.circuit_vector = Some(self.name);
        self
    }

    fn funded(mut self, funding: Vec<FundedNote>) -> Self {
        self.funding = funding;
        self
    }

    fn step(mut self, step: StepSpec) -> Self {
        self.steps.push(step);
        self
    }

    fn default_ring(mut self, status: RingStatus) -> Self {
        self.default_ring = status;
        self
    }

    fn custom_ring(mut self, status: RingStatus) -> Self {
        self.custom_ring = status;
        self
    }
}

/// Group B: who receives what.
fn outputs() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "recipient_outputs_without_data",
            "Every output pays a recipient who authorizes nothing.",
        )
        .linked()
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("r0", Recipient(0), Sol, 40),
                pay("r1", Recipient(1), Sol, 30),
                pay("r2", Recipient(0), Sol, 20),
                pay("r3", Recipient(1), Sol, 10),
            ],
        )),
        hidden_spend(
            "self_transfer",
            "The hidden owner splits its note into two notes of its own.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("c0", Hidden, Sol, 60), pay("c1", Hidden, Sol, 40)],
        )),
        hidden_spend(
            "two_recipients_and_change",
            "Two recipients and the hidden owner's change in one transaction.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("r0", Recipient(0), Sol, 50),
                pay("r1", Recipient(1), Sol, 30),
                pay("c0", Hidden, Sol, 20),
            ],
        )),
        hidden_spend(
            "zero_amount_output",
            "A real output carries amount zero beside the full change.",
        )
        .linked()
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("r0", Recipient(0), Sol, 0), pay("c0", Hidden, Sol, 100)],
        )),
        hidden_spend(
            "exact_spend_no_change",
            "Two notes pay one recipient exactly; no change output exists.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 70),
            note("h1", Hidden, Sol, 30),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![pay("r0", Recipient(0), Sol, 100)],
        )),
    ]
}

/// Group C: how the slots past the real ones are filled.
fn padding() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "compact_input_padding",
            "One real input followed by compact input slots.",
        )
        .linked()
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .compact()
            .slots(3, 2),
        ),
        hidden_spend(
            "non_compact_dummy_input",
            "One real input followed by a dummy input that publishes its nullifier.",
        )
        .linked()
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .slots(2, 2),
        ),
        hidden_spend(
            "compact_outputs",
            "Two real outputs followed by compact output slots.",
        )
        .linked()
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .compact()
            .slots(1, 4),
        ),
        hidden_spend(
            "trailing_dummy_outputs",
            "One real output followed by dummy outputs that publish a hash and a participant's tag.",
        )
        .linked()
        .step(
            StepSpec::new(vec![spend("h0")], vec![pay("r0", Recipient(0), Sol, 100)])
                .slots(1, 4),
        ),
        hidden_spend(
            "dummy_output_tags",
            "A hidden note and a co-signer's note pay one default-ring output; the dummy outputs publish participants' tags.",
        )
        .linked()
        .funded(vec![note("h0", Hidden, Sol, 100), note("s0", Signer(0), Sol, 50)])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Recipient(0), Sol, 150).default_ring()],
            )
            .signers(&[Signer(0)])
            .slots(2, 4),
        ),
    ]
}

/// Group D: value entering and leaving through public accounts.
fn public_value() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "public_deposit",
            "A public SOL deposit tops up a hidden spend.",
        )
        .linked()
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Hidden, Sol, 30)],
            )
            .public(vec![deposit(Sol, 50, Funder(0))]),
        ),
        hidden_spend(
            "public_withdrawal",
            "A hidden spend withdraws part of its value to a public account.",
        )
        .linked()
        .funded(vec![note("h0", Hidden, Sol, 70), note("h1", Hidden, Sol, 30)])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("h1")],
                vec![pay("r0", Recipient(0), Sol, 50), pay("c0", Hidden, Sol, 10)],
            )
            .public(vec![withdraw(Sol, 40, Recipient(1))]),
        ),
        hidden_spend(
            "full_withdrawal",
            "The hidden owner withdraws its whole note; only a zero-amount change remains private.",
        )
        .step(
            StepSpec::new(vec![spend("h0")], vec![pay("c0", Hidden, Sol, 0)])
                .public(vec![withdraw(Sol, 100, Recipient(0))]),
        ),
        hidden_spend(
            "spl_deposit",
            "A public SPL deposit lands as the hidden owner's note beside a SOL payment.",
        )
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![
                    pay("r0", Recipient(0), Sol, 60),
                    pay("c0", Hidden, Sol, 40),
                    pay("c1", Hidden, SplA, 500),
                ],
            )
            .public(vec![deposit(SplA, 500, Funder(0))]),
        ),
        hidden_spend(
            "spl_withdrawal",
            "A hidden SPL note withdraws part of its value to a public token account.",
        )
        .funded(vec![note("h0", Hidden, SplA, 500)])
        .step(
            StepSpec::new(vec![spend("h0")], vec![pay("c0", Hidden, SplA, 300)])
                .public(vec![withdraw(SplA, 200, Recipient(0))]),
        ),
        hidden_spend(
            "token_2022_deposit_and_withdrawal",
            "A Token-2022 deposit becomes the hidden owner's note, which a second step withdraws in part.",
        )
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("c0", Hidden, Sol, 100), pay("t0", Hidden, Token2022A, 300)],
            )
            .public(vec![deposit(Token2022A, 300, Funder(0))]),
        )
        .step(
            StepSpec::new(vec![spend("t0")], vec![pay("t1", Hidden, Token2022A, 200)])
                .public(vec![withdraw(Token2022A, 100, Recipient(0))]),
        ),
        hidden_spend(
            "three_public_slots",
            "Three distinct public assets in one transaction: a SOL withdrawal and two SPL deposits.",
        )
        .linked()
        .funded(vec![note("h0", Hidden, Sol, 100), note("h1", Hidden, SplA, 80)])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("h1")],
                vec![
                    pay("r0", Recipient(0), Sol, 90),
                    pay("r1", Recipient(0), SplA, 100),
                    pay("r2", Recipient(1), SplB, 25),
                    pay("c0", Hidden, Sol, 0),
                ],
            )
            .public(vec![
                withdraw(Sol, 10, Recipient(2)),
                deposit(SplA, 20, Funder(0)),
                deposit(SplB, 25, Funder(0)),
            ]),
        ),
        hidden_spend(
            "deposit_and_withdrawal_of_different_assets",
            "One asset is withdrawn while another is deposited in the same transaction.",
        )
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("c0", Hidden, Sol, 70), pay("r0", Recipient(0), SplA, 50)],
            )
            .public(vec![withdraw(Sol, 30, Recipient(1)), deposit(SplA, 50, Funder(0))]),
        ),
        hidden_spend(
            "two_withdrawal_legs_one_asset",
            "Two public recipients withdraw the same asset in one transaction.",
        )
        .step(
            StepSpec::new(vec![spend("h0")], vec![pay("c0", Hidden, Sol, 50)]).public(vec![
                withdraw(Sol, 20, Recipient(0)),
                withdraw(Sol, 30, Recipient(1)),
            ]),
        ),
    ]
}

/// Group E: several assets in one private transaction.
fn assets() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "multi_asset_private",
            "Three assets balance independently with no public movement.",
        )
        .linked()
        .funded(vec![
            note("h0", Hidden, Sol, 100),
            note("h1", Hidden, SplA, 50),
            note("h2", Hidden, SplB, 7),
        ])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("h1"), spend("h2")],
                vec![
                    pay("r0", Recipient(0), Sol, 100),
                    pay("r1", Recipient(0), SplA, 50),
                    pay("c0", Hidden, SplB, 7),
                ],
            )
            .slots(3, 4),
        ),
        hidden_spend(
            "sol_and_spl_private",
            "A SOL note and an SPL note pay one recipient both assets, with SOL change.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 100),
            note("h1", Hidden, SplA, 40),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![
                pay("r0", Recipient(0), Sol, 60),
                pay("r1", Recipient(0), SplA, 40),
                pay("c0", Hidden, Sol, 40),
            ],
        )),
        hidden_spend(
            "one_asset_many_note_sizes",
            "Notes of very different sizes of one asset combine into one payment.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 1),
            note("h1", Hidden, Sol, 10),
            note("h2", Hidden, Sol, 100),
            note("h3", Hidden, Sol, 1_000),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1"), spend("h2"), spend("h3")],
            vec![
                pay("r0", Recipient(0), Sol, 1_000),
                pay("c0", Hidden, Sol, 111),
            ],
        )),
    ]
}

/// Group F: address slots, which publish a nullifier and carry no value.
fn addresses() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "hidden_note_then_hidden_address",
            "The hidden owner's note followed by a fresh address of the same owner.",
        )
        .linked()
        .default_ring(pending(ADDRESSES_FIRST))
        .step(StepSpec::new(
            vec![spend("h0"), address(Hidden, 0xa1)],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
        hidden_spend(
            "hidden_address_then_hidden_note",
            "A fresh address of the hidden owner followed by its note.",
        )
        .linked()
        .custom_ring(not_applicable(HIDDEN_FIRST))
        .step(StepSpec::new(
            vec![address(Hidden, 0xa2), spend("h0")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
        hidden_spend(
            "signer_address_beside_hidden_note",
            "The hidden owner's note followed by a public co-owner's fresh address.",
        )
        .linked()
        .default_ring(pending(ADDRESSES_FIRST))
        .step(
            StepSpec::new(
                vec![spend("h0"), address(Signer(0), 0xa3)],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .signers(&[Signer(0)]),
        ),
        hidden_spend(
            "signer_address_then_hidden_note",
            "A public co-owner's fresh address followed by the hidden owner's note.",
        )
        .custom_ring(not_applicable(HIDDEN_FIRST))
        .step(
            StepSpec::new(
                vec![address(Signer(0), 0xa4), spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .signers(&[Signer(0)]),
        ),
        hidden_spend(
            "hidden_address_only_with_deposit",
            "A fresh address is the only input; a public deposit funds the hidden owner's note.",
        )
        .linked()
        .funded(Vec::new())
        .step(
            StepSpec::new(
                vec![address(Hidden, 0xa5)],
                vec![pay("c0", Hidden, Sol, 40)],
            )
            .public(vec![deposit(Sol, 40, Funder(0))])
            .slots(1, 2),
        ),
    ]
}

/// Group G: outputs that carry a data hash, and spending them.
fn data() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "signer_owned_data_output",
            "An output with a data hash is owned by a public co-owner.",
        )
        .linked()
        .funded(vec![
            note("h0", Hidden, Sol, 100),
            note("s0", Signer(0), Sol, 50),
        ])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![
                    pay("d0", Signer(0), Sol, 120).with_data(0xd1),
                    pay("c0", Hidden, Sol, 30),
                ],
            )
            .signers(&[Signer(0)]),
        ),
        VectorSpec {
            circuit_vector: Some("hidden_owned_ring_data_output"),
            ..hidden_spend(
                "hidden_owned_data_output",
                "An output with a data hash is owned by the hidden owner.",
            )
        }
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("d0", Hidden, Sol, 100).with_data(0xd2),
                pay("r0", Recipient(0), Sol, 0),
            ],
        )),
        hidden_spend(
            "spend_note_with_data_hash",
            "The hidden owner creates a note with a data hash, then spends it.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("d0", Hidden, Sol, 100).with_data(0xd3)],
        ))
        .step(StepSpec::new(
            vec![spend("d0")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
    ]
}

/// Group H: inputs from several trees, outputs to another tree, the cache.
fn trees() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "inputs_across_two_trees",
            "Two notes of the hidden owner are spent from two trees in one transaction.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 70),
            note("h1", Hidden, Sol, 30).in_tree(1),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
        hidden_spend(
            "equal_notes_in_two_trees",
            "Notes of equal owner, asset and amount in two trees are both spent.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 50),
            note("h1", Hidden, Sol, 50).in_tree(1),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
        hidden_spend(
            "output_to_other_tree",
            "A note from one tree pays outputs appended to another tree.",
        )
        .step(
            StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )
            .output_tree(1),
        ),
        hidden_spend(
            "cached_input_beside_state_input",
            "One input proves existence through the tree's cache, the other through the state tree.",
        )
        .linked()
        .funded(vec![note("h0", Hidden, Sol, 70), note("h1", Hidden, Sol, 30)])
        .step(StepSpec::new(
            vec![spend("h0"), spend_cached("h1")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
        VectorSpec {
            circuit_vector: Some("cached_input_without_state_root"),
            ..hidden_spend(
                "cached_input_only",
                "The only input, a default-ring note, proves existence through the tree's cache, so the transaction opens no state root.",
            )
        }
        .funded(vec![note("h0", Hidden, Sol, 100).default_ring()])
        .step(StepSpec::new(
            vec![spend_cached("h0")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        )),
    ]
}

/// Group I: the widest transactions each ring supports.
fn shapes() -> Vec<VectorSpec> {
    let notes = |count: u64| -> (Vec<FundedNote>, Vec<String>) {
        (1..=count)
            .map(|index| {
                let id = format!("h{index}");
                (note(&id, Hidden, Sol, index), id)
            })
            .unzip()
    };
    let (wide_24, ids_24) = notes(24);
    let (wide_48, ids_48) = notes(48);
    let spends = |ids: Vec<String>| ids.iter().map(|id| spend(id)).collect();
    let payments = |count: u8, amount: u64| {
        (0..count)
            .map(|index| pay(&format!("r{index}"), Recipient(index % 2), Sol, amount))
            .collect()
    };
    vec![
        hidden_spend(
            "widest_common_inputs",
            "Twenty-four notes in one transaction, the widest input count both rings support.",
        )
        .funded(wide_24)
        .step(StepSpec::new(spends(ids_24), vec![pay("r0", Recipient(0), Sol, 300)]).compact()),
        hidden_spend(
            "widest_common_outputs",
            "One note pays eight outputs, the widest output count both rings support.",
        )
        .funded(vec![note("h0", Hidden, Sol, 80)])
        .step(StepSpec::new(vec![spend("h0")], payments(8, 10))),
        hidden_spend(
            "eight_inputs_eight_outputs",
            "Eight notes pay eight outputs.",
        )
        .linked()
        .custom_ring(not_applicable(NO_ANONYMOUS_KEY))
        .funded(vec![
            note("h0", Hidden, Sol, 10),
            note("h1", Hidden, Sol, 11),
            note("h2", Hidden, Sol, 12),
            note("h3", Hidden, Sol, 13),
            note("h4", Hidden, Sol, 14),
            note("h5", Hidden, Sol, 15),
            note("h6", Hidden, Sol, 16),
            note("h7", Hidden, Sol, 17),
        ])
        .step(StepSpec::new(
            vec![
                spend("h0"),
                spend("h1"),
                spend("h2"),
                spend("h3"),
                spend("h4"),
                spend("h5"),
                spend("h6"),
                spend("h7"),
            ],
            vec![
                pay("r0", Recipient(0), Sol, 20),
                pay("r1", Recipient(1), Sol, 20),
                pay("r2", Recipient(0), Sol, 20),
                pay("r3", Recipient(1), Sol, 20),
                pay("r4", Recipient(0), Sol, 10),
                pay("r5", Recipient(1), Sol, 10),
                pay("r6", Recipient(0), Sol, 5),
                pay("c0", Hidden, Sol, 3),
            ],
        )),
        hidden_spend(
            "one_input_sixteen_outputs",
            "One note pays sixteen outputs.",
        )
        .linked()
        .custom_ring(not_applicable(NO_ANONYMOUS_KEY))
        .funded(vec![note("h0", Hidden, Sol, 160)])
        .step(StepSpec::new(vec![spend("h0")], payments(16, 10))),
        hidden_spend(
            "forty_eight_inputs",
            "Forty-eight notes in one transaction, the default ring's widest input count.",
        )
        .custom_ring(not_applicable(NO_ANONYMOUS_KEY))
        .funded(wide_48)
        .step(StepSpec::new(spends(ids_48), vec![pay("r0", Recipient(0), Sol, 1_176)]).compact()),
    ]
}

/// Group J: value crossing between a custom ring and the default ring.
fn ring_boundary() -> Vec<VectorSpec> {
    let boundary = |name, description| {
        hidden_spend(name, description)
            .linked()
            .default_ring(not_applicable(NO_RING_NOTES))
    };
    vec![
        boundary(
            "default_hidden_deposit_into_ring",
            "Two default-ring notes of the hidden owner move into the ring.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 70).default_ring(),
            note("h1", Hidden, Sol, 30).default_ring(),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![pay("c0", Hidden, Sol, 100), pay("r0", Recipient(0), Sol, 0)],
        )),
        boundary(
            "exit_to_default_recipient",
            "A ring note pays a default-ring recipient and keeps ring change.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("r0", Recipient(0), Sol, 60).default_ring(),
                pay("c0", Hidden, Sol, 40),
            ],
        )),
        boundary(
            "default_hidden_stays_default",
            "Every note of a ring transfer is a default-ring note.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 70).default_ring(),
            note("h1", Hidden, Sol, 30).default_ring(),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1")],
            vec![
                pay("r0", Recipient(0), Sol, 60).default_ring(),
                pay("c0", Hidden, Sol, 40).default_ring(),
            ],
        )),
        boundary(
            "ring_hidden_beside_signer_default",
            "A hidden ring note beside a public co-owner's default-ring note.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 100),
            note("s0", Signer(0), Sol, 50).default_ring(),
        ])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Signer(0), Sol, 30)],
            )
            .signers(&[Signer(0)]),
        ),
        boundary(
            "default_hidden_beside_signer_ring",
            "A hidden default-ring note beside a public co-owner's ring note.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 100).default_ring(),
            note("s0", Signer(0), Sol, 50),
        ])
        .step(
            StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Signer(0), Sol, 30)],
            )
            .signers(&[Signer(0)]),
        ),
        boundary(
            "dummy_output_tag_default_owner",
            "A hidden default-ring note pays a ring recipient; the dummy output names the published owner.",
        )
        .funded(vec![note("h0", Hidden, Sol, 100).default_ring()])
        .step(
            StepSpec::new(vec![spend("h0")], vec![pay("r0", Recipient(0), Sol, 100)]).slots(1, 2),
        ),
        boundary(
            "deposit_and_exit_mixed",
            "Ring notes of the hidden owner pay ring and default-ring outputs.",
        )
        .funded(vec![
            note("h0", Hidden, Sol, 100),
            note("h1", Hidden, Sol, 40),
            note("h2", Hidden, Sol, 10),
            note("h3", Hidden, Sol, 5),
        ])
        .step(StepSpec::new(
            vec![spend("h0"), spend("h1"), spend("h2"), spend("h3")],
            vec![
                pay("r0", Recipient(0), Sol, 80),
                pay("r1", Recipient(0), Sol, 50).default_ring(),
                pay("c0", Hidden, Sol, 20),
                pay("r2", Recipient(1), Sol, 5).default_ring(),
            ],
        )),
        boundary(
            "hidden_owned_default_data_output",
            "A hidden default-ring note pays the owner's own default-ring output with a data hash.",
        )
        .funded(vec![note("h0", Hidden, Sol, 100).default_ring()])
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("d0", Hidden, Sol, 100).default_ring().with_data(0xd4),
                pay("r0", Recipient(0), Sol, 0),
            ],
        )),
        hidden_spend(
            "exit_to_same_owner",
            "The hidden owner moves part of a ring note to its own default-ring note.",
        )
        .default_ring(not_applicable(NO_RING_NOTES))
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![
                pay("c0", Hidden, Sol, 60).default_ring(),
                pay("c1", Hidden, Sol, 40),
            ],
        )),
    ]
}

/// Group K: scenarios of several transactions, each spending what an earlier one created.
fn multi_step() -> Vec<VectorSpec> {
    vec![
        hidden_spend(
            "second_payment_to_same_recipient",
            "The hidden owner pays one recipient twice, the second time from its change.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("r0", Recipient(0), Sol, 30), pay("c0", Hidden, Sol, 70)],
        ))
        .step(StepSpec::new(
            vec![spend("c0")],
            vec![pay("r1", Recipient(0), Sol, 20), pay("c1", Hidden, Sol, 50)],
        )),
        hidden_spend(
            "recipient_spends_back",
            "A recipient spends the note it received, authorizing inside the proof, and pays the sender back.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
        ))
        .step(
            StepSpec::new(
                vec![spend("r0")],
                vec![pay("b0", Hidden, Sol, 25), pay("c1", Recipient(0), Sol, 35)],
            )
            .hidden_owner(Recipient(0)),
        ),
        hidden_spend(
            "change_chain",
            "Three transactions in a row, each spending the previous one's change.",
        )
        .step(StepSpec::new(
            vec![spend("h0")],
            vec![pay("r0", Recipient(0), Sol, 10), pay("c0", Hidden, Sol, 90)],
        ))
        .step(StepSpec::new(
            vec![spend("c0")],
            vec![pay("r1", Recipient(0), Sol, 20), pay("c1", Hidden, Sol, 70)],
        ))
        .step(StepSpec::new(
            vec![spend("c1")],
            vec![pay("r2", Recipient(0), Sol, 30), pay("c2", Hidden, Sol, 40)],
        )),
    ]
}

/// Group A: who owns the inputs and how each owner authorizes.
fn ownership() -> Vec<VectorSpec> {
    vec![
        VectorSpec {
            name: "hidden_ring_note",
            description: "One hidden-owner note pays a recipient and keeps change.",
            circuit_vector: Some("hidden_ring_note"),
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100)],
            steps: vec![StepSpec::new(
                vec![spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 60), pay("c0", Hidden, Sol, 40)],
            )],
        },
        VectorSpec {
            name: "hidden_two_notes",
            description: "Two notes of the hidden owner pay a recipient and keep change.",
            circuit_vector: Some("hidden_two_notes"),
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100), note("h1", Hidden, Sol, 50)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("h1")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Hidden, Sol, 30)],
            )],
        },
        VectorSpec {
            name: "no_signers",
            description: "Every input is the hidden owner's and no owner signs the transaction; the change is zero.",
            circuit_vector: Some("no_signers"),
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 70), note("h1", Hidden, Sol, 30)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("h1")],
                vec![pay("r0", Recipient(0), Sol, 100), pay("c0", Hidden, Sol, 0)],
            )],
        },
        VectorSpec {
            name: "hidden_then_signer",
            description: "A hidden owner's note in slot 0 beside a public co-owner's note in slot 1; the co-owner keeps the change.",
            circuit_vector: Some("hidden_then_signer"),
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100), note("s0", Signer(0), Sol, 50)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Signer(0), Sol, 30)],
            )
            .signers(&[Signer(0)])],
        },
        VectorSpec {
            name: "signer_then_hidden",
            description: "A public co-owner's note in slot 0 beside the hidden owner's note in slot 1.",
            circuit_vector: Some("signer_then_hidden"),
            default_ring: run(),
            custom_ring: not_applicable(HIDDEN_FIRST),
            funding: vec![note("s0", Signer(0), Sol, 50), note("h0", Hidden, Sol, 100)],
            steps: vec![StepSpec::new(
                vec![spend("s0"), spend("h0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Hidden, Sol, 30)],
            )
            .signers(&[Signer(0)])],
        },
        VectorSpec {
            name: "two_signers",
            description: "The hidden owner's note beside two public co-owners' notes; the second co-owner keeps change.",
            circuit_vector: Some("two_signers"),
            default_ring: run(),
            custom_ring: run(),
            funding: vec![
                note("h0", Hidden, Sol, 100),
                note("s0", Signer(0), Sol, 50),
                note("s1", Signer(1), Sol, 25),
            ],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("s0"), spend("s1")],
                vec![pay("r0", Recipient(0), Sol, 150), pay("c0", Signer(1), Sol, 25)],
            )
            .signers(&[Signer(0), Signer(1)])],
        },
        VectorSpec {
            name: "three_signers",
            description: "The hidden owner's note beside three public co-owners' notes, the most owners a custom ring screens in one transfer.",
            circuit_vector: None,
            default_ring: run(),
            custom_ring: run(),
            funding: vec![
                note("h0", Hidden, Sol, 100),
                note("s0", Signer(0), Sol, 40),
                note("s1", Signer(1), Sol, 30),
                note("s2", Signer(2), Sol, 20),
            ],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("s0"), spend("s1"), spend("s2")],
                vec![pay("r0", Recipient(0), Sol, 150), pay("c0", Hidden, Sol, 40)],
            )
            .signers(&[Signer(0), Signer(1), Signer(2)])],
        },
        VectorSpec {
            name: "unused_signer",
            description: "A listed public signer owns no input; the hidden owner spends alone.",
            circuit_vector: Some("unused_signer"),
            default_ring: pending(SIGNERS_FROM_INPUTS),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100), note("h1", Hidden, Sol, 20)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("h1")],
                vec![pay("r0", Recipient(0), Sol, 100), pay("c0", Hidden, Sol, 20)],
            )
            .signers(&[Signer(0)])],
        },
        VectorSpec {
            name: "fee_payer_is_co_owner",
            description: "The fee payer also owns an input and signs once for both roles.",
            circuit_vector: None,
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100), note("p0", Payer, Sol, 50)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("p0")],
                vec![pay("r0", Recipient(0), Sol, 120), pay("c0", Hidden, Sol, 30)],
            )
            .signers(&[Payer])],
        },
        VectorSpec {
            name: "co_owner_receives_payment",
            description: "The hidden owner and a public co-owner pay their whole value to the co-owner.",
            circuit_vector: None,
            default_ring: run(),
            custom_ring: run(),
            funding: vec![
                note("h0", Hidden, Sol, 10_000),
                note("s0", Signer(0), Sol, 1_000),
            ],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Signer(0), Sol, 11_000)],
            )
            .signers(&[Signer(0)])],
        },
        VectorSpec {
            name: "co_owner_only_contributes",
            description: "A public co-owner contributes its note and receives nothing.",
            circuit_vector: None,
            default_ring: run(),
            custom_ring: run(),
            funding: vec![note("h0", Hidden, Sol, 100), note("s0", Signer(0), Sol, 50)],
            steps: vec![StepSpec::new(
                vec![spend("h0"), spend("s0")],
                vec![pay("r0", Recipient(0), Sol, 150)],
            )
            .signers(&[Signer(0)])],
        },
    ]
}
