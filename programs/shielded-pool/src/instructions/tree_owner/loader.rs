use pinocchio::{error::ProgramError, AccountView};
use spr_interface::{error::ShieldedPoolError, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR};
use spr_tree::TreeAccount;

use crate::instructions::shared::caused_by;

/// Require a tree account created before trees could have an owner: writable,
/// owned by the program, initialized, and still at the size `resize_tree`
/// grows.
#[inline(never)]
pub(crate) fn load_legacy_tree(tree: &AccountView) -> Result<(), ProgramError> {
    if !tree.is_writable() || !tree.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    let data = tree
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::InvalidTreeAccounts))?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    if data.len() != TreeAccount::legacy_account_size() {
        return Err(ShieldedPoolError::TreeNotResizable.into());
    }
    Ok(())
}
