#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use spr_tree::{NullifierTreeInitParams, TreeFeeSchedule};

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateTreeData {
    pub tree_id: u16,
    pub nullifier_params: NullifierTreeInitParams,
    pub fees: TreeFeeSchedule,
    /// The address that must sign every deposit, transact and merge that
    /// writes the tree; `None` for a tree anyone may use. Set at creation and
    /// never changed. The program rejects the zero address.
    pub owner: Option<Address>,
}
