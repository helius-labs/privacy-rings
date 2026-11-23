//! The exported shape of `test-vectors/transact_functional.json`.
//!
//! A vector describes one successful scenario in ring-agnostic terms: who acts,
//! which notes exist before the scenario, the ordered transactions, and the
//! state every runner must observe afterwards. It never stores proofs, tree
//! positions, blindings or instruction bytes: those differ per run and per
//! ring, so each runner derives them.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionalVectorFile {
    pub description: String,
    /// Dimension value -> names of the vectors that exercise it.
    pub coverage: BTreeMap<String, Vec<String>>,
    pub vectors: Vec<FunctionalVector>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionalVector {
    pub name: String,
    pub description: String,
    /// The case of the same name in `anonymous_eddsa_accepting.json`, when one exists.
    pub circuit_vector: Option<String>,
    pub rings: RingStatuses,
    /// Every role the vector names, with the 32-byte seed of its ed25519 key.
    pub actors: BTreeMap<Role, Seed>,
    /// Notes that exist before the first step, created by proofless deposits.
    pub funding: Vec<FundedNote>,
    pub steps: Vec<Step>,
    /// Each actor's unspent notes after the last step, sorted.
    pub unspent_after: BTreeMap<Role, Vec<NoteBalance>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RingStatuses {
    pub default: RingStatus,
    pub custom: RingStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RingStatus {
    Run,
    /// The ring cannot express the case by design.
    NotApplicable {
        reason: String,
    },
    /// The ring should support the case, but no runner settles it yet.
    Pending {
        reason: String,
    },
}

impl RingStatus {
    pub fn is_run(&self) -> bool {
        matches!(self, RingStatus::Run)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FundedNote {
    pub id: String,
    pub owner: Role,
    pub asset: Asset,
    #[serde(with = "decimal")]
    pub amount: u64,
    /// A ring note when the vector runs in a custom ring; a default-ring run ignores it.
    pub ring: bool,
    /// Index of the tree the deposit lands in, 0 or 1.
    pub tree: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    /// The real input slots, in order.
    pub inputs: Vec<InputSlot>,
    /// The real output slots, in order.
    pub outputs: Vec<OutputSlot>,
    pub public: Vec<PublicLeg>,
    /// The owner that authorizes inside the proof and never signs the transaction.
    pub hidden_owner: Role,
    /// Owners that authorize as transaction signers, in signer-vector order.
    pub signers: Vec<Role>,
    pub fee_payer: Role,
    /// Index of the tree the outputs are appended to.
    pub output_tree: u8,
    /// How the runner fills the slots past the real ones.
    pub padding: Padding,
    /// The runner picks a shape with at least this many input slots.
    pub min_input_slots: u8,
    /// The runner picks a shape with at least this many output slots.
    pub min_output_slots: u8,
    pub expect: StepExpectations,
}

/// How the slots past the real ones are filled. A client picks one mode per
/// transaction; the shape, and with it the number of padding slots, is the
/// runner's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Padding {
    /// Dummy inputs publish a nullifier and dummy outputs a hash and a participant's tag.
    Dummy,
    /// Compact slots publish nothing and reveal the real counts.
    Compact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputSlot {
    /// Spends a funded note or an output of an earlier step.
    Utxo {
        note: String,
        owner: Role,
        authorization: Authorization,
        /// Proves existence through the tree's cache instead of the state tree.
        cached: bool,
    },
    /// Consumes a fresh address: non-inclusion only, no value.
    Address {
        owner: Role,
        authorization: Authorization,
        seed: Seed,
        tree: u8,
    },
}

impl InputSlot {
    pub fn owner(&self) -> Role {
        match self {
            InputSlot::Utxo { owner, .. } | InputSlot::Address { owner, .. } => *owner,
        }
    }

    pub fn authorization(&self) -> Authorization {
        match self {
            InputSlot::Utxo { authorization, .. } | InputSlot::Address { authorization, .. } => {
                *authorization
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    /// Signs inside the proof; never a transaction signer.
    Hidden,
    /// Signs the transaction.
    Signer,
}

/// A real output note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputSlot {
    /// Names the note so a later step can spend it.
    pub id: String,
    pub owner: Role,
    pub asset: Asset,
    #[serde(with = "decimal")]
    pub amount: u64,
    pub ring: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data_hash: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicLeg {
    pub direction: Direction,
    pub asset: Asset,
    #[serde(with = "decimal")]
    pub amount: u64,
    /// The public account that pays a deposit or receives a withdrawal.
    pub account: Role,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Deposit,
    Withdrawal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepExpectations {
    /// The transaction's signers: the fee payer, then the public owners, deduplicated.
    pub transaction_signers: Vec<Role>,
    /// Roles whose key must not sign the transaction.
    pub absent_signers: Vec<Role>,
    /// Real inputs; each publishes a nullifier. Dummy padding adds more.
    pub real_inputs: u32,
    /// Real outputs; each appends a leaf. Dummy padding adds more.
    pub real_outputs: u32,
    /// Public balance change per role and asset; positive receives.
    pub public_deltas: BTreeMap<Role, BTreeMap<Asset, SignedAmount>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteBalance {
    pub asset: Asset,
    #[serde(with = "decimal")]
    pub amount: u64,
    pub ring: bool,
}

/// A role a vector assigns to one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Role {
    /// The default hidden owner of every step.
    Hidden,
    /// Pays fees; may also own inputs as a public co-owner.
    Payer,
    /// A public owner that signs the transaction.
    Signer(u8),
    /// Receives notes or public withdrawals; may be a later step's hidden owner.
    Recipient(u8),
    /// Pays public deposits.
    Funder(u8),
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Hidden => write!(f, "hidden"),
            Role::Payer => write!(f, "payer"),
            Role::Signer(index) => write!(f, "signer{index}"),
            Role::Recipient(index) => write!(f, "recipient{index}"),
            Role::Funder(index) => write!(f, "funder{index}"),
        }
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let indexed = |prefix: &str| {
            value
                .strip_prefix(prefix)
                .and_then(|index| index.parse::<u8>().ok())
        };
        match value {
            "hidden" => Ok(Role::Hidden),
            "payer" => Ok(Role::Payer),
            _ => indexed("signer")
                .map(Role::Signer)
                .or_else(|| indexed("recipient").map(Role::Recipient))
                .or_else(|| indexed("funder").map(Role::Funder))
                .ok_or_else(|| format!("unknown role {value}")),
        }
    }
}

impl TryFrom<String> for Role {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Role> for String {
    fn from(role: Role) -> Self {
        role.to_string()
    }
}

/// A symbolic asset; each runner maps it to a mint it creates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Asset {
    #[serde(rename = "SOL")]
    Sol,
    #[serde(rename = "SPL_A")]
    SplA,
    #[serde(rename = "SPL_B")]
    SplB,
    /// A Token-2022 mint.
    #[serde(rename = "T22_A")]
    Token2022A,
}

impl Asset {
    pub const ALL: [Asset; 4] = [Asset::Sol, Asset::SplA, Asset::SplB, Asset::Token2022A];

    pub fn label(self) -> &'static str {
        match self {
            Asset::Sol => "SOL",
            Asset::SplA => "SPL_A",
            Asset::SplB => "SPL_B",
            Asset::Token2022A => "T22_A",
        }
    }
}

/// A 32-byte value written as `0x`-prefixed hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hash32(pub [u8; 32]);

/// An ed25519 secret seed.
pub type Seed = Hash32;

impl TryFrom<String> for Hash32 {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| format!("{value} lacks the 0x prefix"))?;
        let bytes = hex::decode(digits).map_err(|error| format!("{value}: {error}"))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| format!("{value} has {} bytes, not 32", bytes.len()))?;
        Ok(Hash32(array))
    }
}

impl From<Hash32> for String {
    fn from(value: Hash32) -> Self {
        format!("0x{}", hex::encode(value.0))
    }
}

/// A public balance change: positive receives, negative pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SignedAmount(pub i128);

impl TryFrom<String> for SignedAmount {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value
            .parse::<i128>()
            .map(SignedAmount)
            .map_err(|error| format!("{value}: {error}"))
    }
}

impl From<SignedAmount> for String {
    fn from(value: SignedAmount) -> Self {
        value.0.to_string()
    }
}

/// Amounts are decimal strings, as in the circuit catalog, so readers in
/// languages without 64-bit integers keep full precision.
mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
