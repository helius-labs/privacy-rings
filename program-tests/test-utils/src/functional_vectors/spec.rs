//! The authoring layer for functional vectors.
//!
//! A case is written as a [`VectorSpec`] of funded notes and steps.
//! [`VectorSpec::build`] refuses a case that cannot settle in any ring (an
//! unbalanced asset, an input owner who does not authorize, more public assets
//! than slots) and derives every expectation, so no expected value is typed by
//! hand.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, ensure, Context, Result};

use super::types::{
    Asset, Authorization, Direction, FunctionalVector, FundedNote, Hash32, InputSlot, NoteBalance,
    OutputSlot, Padding, PublicLeg, RingStatus, RingStatuses, Role, Seed, SignedAmount, Step,
    StepExpectations,
};

/// Public asset slots of one transaction (`N_PUBLIC_SLOTS`).
const PUBLIC_ASSET_SLOTS: usize = 3;
/// Distinct assets the transaction builders accept in one transaction.
const MAX_TRANSACTION_ASSETS: usize = 3;
/// Trees a vector may name: the runner creates two.
const TREES: u8 = 2;

pub struct VectorSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub circuit_vector: Option<&'static str>,
    pub default_ring: RingStatus,
    pub custom_ring: RingStatus,
    pub funding: Vec<FundedNote>,
    pub steps: Vec<StepSpec>,
}

pub struct StepSpec {
    pub inputs: Vec<InputSpec>,
    pub outputs: Vec<OutputSlot>,
    pub public: Vec<PublicLeg>,
    pub hidden_owner: Role,
    pub signers: Vec<Role>,
    pub output_tree: u8,
    pub padding: Padding,
    /// Minimum slot counts; `None` is the real slot count.
    pub min_slots: Option<(u8, u8)>,
}

impl StepSpec {
    /// A step of the `hidden` role with dummy padding and no minimum slot counts.
    pub fn new(inputs: Vec<InputSpec>, outputs: Vec<OutputSlot>) -> Self {
        Self {
            inputs,
            outputs,
            public: Vec::new(),
            hidden_owner: Role::Hidden,
            signers: Vec::new(),
            output_tree: 0,
            padding: Padding::Dummy,
            min_slots: None,
        }
    }

    /// Another role authorizes inside the proof, such as a recipient spending what it received.
    pub fn hidden_owner(mut self, role: Role) -> Self {
        self.hidden_owner = role;
        self
    }

    pub fn signers(mut self, signers: &[Role]) -> Self {
        self.signers = signers.to_vec();
        self
    }

    pub fn public(mut self, legs: Vec<PublicLeg>) -> Self {
        self.public = legs;
        self
    }

    pub fn output_tree(mut self, tree: u8) -> Self {
        self.output_tree = tree;
        self
    }

    pub fn compact(mut self) -> Self {
        self.padding = Padding::Compact;
        self
    }

    /// Require a shape with at least this many slots, so padding exists in every ring.
    pub fn slots(mut self, inputs: u8, outputs: u8) -> Self {
        self.min_slots = Some((inputs, outputs));
        self
    }
}

/// An input as authored; the owner and authorization of a spend come from its note.
pub enum InputSpec {
    Spend { note: String, cached: bool },
    Address { owner: Role, seed: u8, tree: u8 },
}

pub fn spend(note: &str) -> InputSpec {
    InputSpec::Spend {
        note: note.to_string(),
        cached: false,
    }
}

pub fn spend_cached(note: &str) -> InputSpec {
    InputSpec::Spend {
        note: note.to_string(),
        cached: true,
    }
}

/// A fresh address in tree 0; its seed is `seed` repeated under a zero top byte.
pub fn address(owner: Role, seed: u8) -> InputSpec {
    InputSpec::Address {
        owner,
        seed,
        tree: 0,
    }
}

/// A ring note in tree 0 funded by a proofless deposit.
pub fn note(id: &str, owner: Role, asset: Asset, amount: u64) -> FundedNote {
    FundedNote {
        id: id.to_string(),
        owner,
        asset,
        amount,
        ring: true,
        tree: 0,
    }
}

impl FundedNote {
    pub fn default_ring(mut self) -> Self {
        self.ring = false;
        self
    }

    pub fn in_tree(mut self, tree: u8) -> Self {
        self.tree = tree;
        self
    }
}

/// A real ring output.
pub fn pay(id: &str, owner: Role, asset: Asset, amount: u64) -> OutputSlot {
    OutputSlot {
        id: id.to_string(),
        owner,
        asset,
        amount,
        ring: true,
        data_hash: None,
    }
}

impl OutputSlot {
    pub fn default_ring(mut self) -> Self {
        self.ring = false;
        self
    }

    /// A data hash of `byte` repeated under a zero top byte, a canonical BN254 scalar.
    pub fn with_data(mut self, byte: u8) -> Self {
        let mut hash = [byte; 32];
        hash[0] = 0;
        self.data_hash = Some(Hash32(hash));
        self
    }
}

pub fn deposit(asset: Asset, amount: u64, account: Role) -> PublicLeg {
    PublicLeg {
        direction: Direction::Deposit,
        asset,
        amount,
        account,
    }
}

pub fn withdraw(asset: Asset, amount: u64, account: Role) -> PublicLeg {
    PublicLeg {
        direction: Direction::Withdrawal,
        asset,
        amount,
        account,
    }
}

pub fn run() -> RingStatus {
    RingStatus::Run
}

pub fn not_applicable(reason: &str) -> RingStatus {
    RingStatus::NotApplicable {
        reason: reason.to_string(),
    }
}

pub fn pending(reason: &str) -> RingStatus {
    RingStatus::Pending {
        reason: reason.to_string(),
    }
}

/// The fixed seed of a role's ed25519 key, distinct per role.
pub fn role_seed(role: Role) -> Seed {
    let byte = match role {
        Role::Hidden => 0x11,
        Role::Signer(index) => 0x21u8.wrapping_add(index),
        Role::Recipient(index) => 0x31u8.wrapping_add(index),
        Role::Payer => 0x41,
        Role::Funder(index) => 0x51u8.wrapping_add(index),
    };
    Hash32([byte; 32])
}

/// A note that exists at some point of the scenario.
struct Held {
    owner: Role,
    asset: Asset,
    amount: u64,
    ring: bool,
}

impl VectorSpec {
    pub fn build(self) -> Result<FunctionalVector> {
        let name = self.name;
        self.build_checked()
            .with_context(|| format!("functional vector {name}"))
    }

    fn build_checked(self) -> Result<FunctionalVector> {
        ensure!(!self.steps.is_empty(), "a vector has at least one step");
        let mut scenario = Scenario::default();
        for funded in &self.funding {
            ensure!(
                funded.tree < TREES,
                "note {} names tree {}",
                funded.id,
                funded.tree
            );
            scenario.create(
                &funded.id,
                Held {
                    owner: funded.owner,
                    asset: funded.asset,
                    amount: funded.amount,
                    ring: funded.ring,
                },
            )?;
        }

        let mut steps = Vec::with_capacity(self.steps.len());
        for (index, step) in self.steps.into_iter().enumerate() {
            steps.push(
                scenario
                    .step(step)
                    .with_context(|| format!("step {index}"))?,
            );
        }

        let mut unspent_after: BTreeMap<Role, Vec<NoteBalance>> = scenario
            .note_owners
            .iter()
            .map(|role| (*role, Vec::new()))
            .collect();
        for held in scenario.unspent.values() {
            unspent_after
                .entry(held.owner)
                .or_default()
                .push(NoteBalance {
                    asset: held.asset,
                    amount: held.amount,
                    ring: held.ring,
                });
        }
        for notes in unspent_after.values_mut() {
            notes.sort();
        }

        Ok(FunctionalVector {
            name: self.name.to_string(),
            description: self.description.to_string(),
            circuit_vector: self.circuit_vector.map(str::to_string),
            rings: RingStatuses {
                default: self.default_ring,
                custom: self.custom_ring,
            },
            actors: scenario
                .actors
                .into_iter()
                .map(|role| (role, role_seed(role)))
                .collect(),
            funding: self.funding,
            steps,
            unspent_after,
        })
    }
}

#[derive(Default)]
struct Scenario {
    unspent: BTreeMap<String, Held>,
    known_ids: BTreeSet<String>,
    actors: BTreeSet<Role>,
    /// Every role that held a note at some point.
    note_owners: BTreeSet<Role>,
}

impl Scenario {
    fn create(&mut self, id: &str, held: Held) -> Result<()> {
        ensure!(
            self.known_ids.insert(id.to_string()),
            "note id {id} is used twice"
        );
        self.actors.insert(held.owner);
        self.note_owners.insert(held.owner);
        self.unspent.insert(id.to_string(), held);
        Ok(())
    }

    fn step(&mut self, spec: StepSpec) -> Result<Step> {
        let StepSpec {
            inputs,
            outputs,
            public,
            hidden_owner,
            signers,
            output_tree,
            padding,
            min_slots,
        } = spec;
        let fee_payer = Role::Payer;
        ensure!(output_tree < TREES, "output tree {output_tree}");
        ensure!(
            matches!(hidden_owner, Role::Hidden | Role::Recipient(_)),
            "{hidden_owner} cannot be the hidden owner"
        );
        let owners = Owners {
            hidden: hidden_owner,
            signers: signers.iter().copied().collect(),
        };
        ensure!(!inputs.is_empty(), "a step has at least one real input");
        ensure!(!outputs.is_empty(), "a step has at least one real output");

        ensure!(
            owners.signers.len() == signers.len(),
            "a signer is listed twice"
        );
        for signer in &signers {
            ensure!(
                matches!(signer, Role::Signer(_) | Role::Payer),
                "{signer} cannot be a public owner signer"
            );
        }

        // Inputs: resolve spends and authorization.
        let mut balance = AssetBalance::default();
        let mut slots = Vec::with_capacity(inputs.len());
        for (position, input) in inputs.into_iter().enumerate() {
            let slot = match input {
                InputSpec::Spend { note, cached } => {
                    let held = self.unspent.remove(&note).ok_or_else(|| {
                        anyhow!("input {position} spends unknown or spent note {note}")
                    })?;
                    balance.add_in(held.asset, held.amount)?;
                    InputSlot::Utxo {
                        note,
                        owner: held.owner,
                        authorization: owners.authorization(held.owner, position)?,
                        cached,
                    }
                }
                InputSpec::Address { owner, seed, tree } => {
                    ensure!(tree < TREES, "address tree {tree}");
                    self.actors.insert(owner);
                    // A zero top byte keeps the seed a canonical BN254 scalar.
                    let mut seed = [seed; 32];
                    seed[0] = 0;
                    InputSlot::Address {
                        owner,
                        authorization: owners.authorization(owner, position)?,
                        seed: Hash32(seed),
                        tree,
                    }
                }
            };
            slots.push(slot);
        }
        ensure!(
            slots
                .iter()
                .any(|slot| slot.authorization() == Authorization::Hidden),
            "no input is authorized by the hidden owner"
        );

        // Public legs.
        let mut public_assets = BTreeMap::new();
        let mut public_deltas: BTreeMap<Role, BTreeMap<Asset, SignedAmount>> = BTreeMap::new();
        let mut deposit_signers = Vec::new();
        for leg in &public {
            ensure!(leg.amount > 0, "a public leg moves a non-zero amount");
            let previous = public_assets.insert(leg.asset, leg.direction);
            ensure!(
                previous.is_none_or(|direction| direction == leg.direction),
                "{} is both deposited and withdrawn",
                leg.asset.label()
            );
            let signed = match leg.direction {
                Direction::Deposit => {
                    ensure!(
                        matches!(leg.account, Role::Funder(_)),
                        "a deposit is paid by a funder, not {}",
                        leg.account
                    );
                    balance.add_in(leg.asset, leg.amount)?;
                    if !deposit_signers.contains(&leg.account) {
                        deposit_signers.push(leg.account);
                    }
                    -i128::from(leg.amount)
                }
                Direction::Withdrawal => {
                    ensure!(
                        matches!(leg.account, Role::Recipient(_)),
                        "a withdrawal goes to a recipient, not {}",
                        leg.account
                    );
                    balance.add_out(leg.asset, leg.amount)?;
                    i128::from(leg.amount)
                }
            };
            self.actors.insert(leg.account);
            let entry = public_deltas
                .entry(leg.account)
                .or_default()
                .entry(leg.asset)
                .or_insert(SignedAmount(0));
            entry.0 = entry
                .0
                .checked_add(signed)
                .ok_or_else(|| anyhow!("public delta overflows"))?;
        }
        ensure!(
            public_assets.len() <= PUBLIC_ASSET_SLOTS,
            "{} public assets exceed {PUBLIC_ASSET_SLOTS} slots",
            public_assets.len()
        );

        // Outputs: data authorization and new notes.
        for (position, output) in outputs.iter().enumerate() {
            if output.data_hash.is_some() {
                ensure!(
                    owners.authorizes(output.owner),
                    "output {position} carries data but its owner {} does not authorize",
                    output.owner
                );
            }
            balance.add_out(output.asset, output.amount)?;
            self.create(
                &output.id,
                Held {
                    owner: output.owner,
                    asset: output.asset,
                    amount: output.amount,
                    ring: output.ring,
                },
            )?;
        }
        balance.check()?;
        let assets = balance.assets();
        ensure!(
            assets <= MAX_TRANSACTION_ASSETS,
            "{assets} distinct assets exceed {MAX_TRANSACTION_ASSETS}"
        );

        let real_inputs = u8::try_from(slots.len()).context("real input count")?;
        let real_outputs = u8::try_from(outputs.len()).context("real output count")?;
        let (min_input_slots, min_output_slots) = min_slots.unwrap_or((real_inputs, real_outputs));
        ensure!(
            min_input_slots >= real_inputs && min_output_slots >= real_outputs,
            "minimum slots {min_input_slots}x{min_output_slots} hold fewer than the real slots"
        );

        self.actors.extend(signers.iter().copied());
        self.actors.insert(hidden_owner);
        self.actors.insert(fee_payer);

        let mut transaction_signers = vec![fee_payer];
        for role in signers.iter().chain(deposit_signers.iter()) {
            if !transaction_signers.contains(role) {
                transaction_signers.push(*role);
            }
        }
        Ok(Step {
            inputs: slots,
            outputs,
            public,
            hidden_owner,
            signers,
            fee_payer,
            output_tree,
            padding,
            min_input_slots,
            min_output_slots,
            expect: StepExpectations {
                transaction_signers,
                absent_signers: vec![hidden_owner],
                real_inputs: u32::from(real_inputs),
                real_outputs: u32::from(real_outputs),
                public_deltas,
            },
        })
    }
}

/// The owners that authorize one step.
struct Owners {
    hidden: Role,
    signers: BTreeSet<Role>,
}

impl Owners {
    fn authorizes(&self, owner: Role) -> bool {
        owner == self.hidden || self.signers.contains(&owner)
    }

    fn authorization(&self, owner: Role, position: usize) -> Result<Authorization> {
        if owner == self.hidden {
            Ok(Authorization::Hidden)
        } else if self.signers.contains(&owner) {
            Ok(Authorization::Signer)
        } else {
            bail!(
                "input {position} is owned by {owner}, who is neither the hidden owner nor a listed signer"
            )
        }
    }
}

/// Per-asset value entering (inputs, deposits) and leaving (outputs, withdrawals).
#[derive(Default)]
struct AssetBalance(BTreeMap<Asset, (u128, u128)>);

impl AssetBalance {
    fn add_in(&mut self, asset: Asset, amount: u64) -> Result<()> {
        let entry = self.0.entry(asset).or_default();
        entry.0 = entry
            .0
            .checked_add(u128::from(amount))
            .context("input sum")?;
        Ok(())
    }

    fn add_out(&mut self, asset: Asset, amount: u64) -> Result<()> {
        let entry = self.0.entry(asset).or_default();
        entry.1 = entry
            .1
            .checked_add(u128::from(amount))
            .context("output sum")?;
        Ok(())
    }

    fn check(&self) -> Result<()> {
        for (asset, (entering, leaving)) in &self.0 {
            ensure!(
                entering == leaving,
                "{} does not balance: {entering} in, {leaving} out",
                asset.label()
            );
        }
        Ok(())
    }

    fn assets(&self) -> usize {
        self.0.len()
    }
}
