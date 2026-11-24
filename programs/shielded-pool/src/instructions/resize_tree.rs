use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::Transfer;
use spr_account_checks::AccountIterator;
use spr_interface::{error::ShieldedPoolError, state::tree_account_size};
use spr_tree::TreeAccount;

use crate::instructions::tree_owner::loader::load_legacy_tree;

/// Grow a tree account created before trees could have an owner to the
/// current layout. The owner is the last field, so no other byte moves, and
/// the zero fill of the growth reads as unowned: the instruction can only
/// produce an unowned tree of the current size. That makes it safe for anyone
/// to send, on a paused tree too, and a second call fails the size check.
///
/// `payer` funds the rent the added bytes cost. The tree's own lamports above
/// its rent minimum are fee balance and nullifier-PDA working capital, so they
/// are not used.
pub fn process_resize_tree(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let tree = iter.next_mut("tree")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }
    load_legacy_tree(tree)?;

    let rent = Rent::get()?;
    let added_rent = rent
        .try_minimum_balance(tree_account_size())?
        .checked_sub(rent.try_minimum_balance(TreeAccount::legacy_account_size())?)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if added_rent > 0 {
        Transfer {
            from: payer,
            to: tree,
            lamports: added_rent,
        }
        .invoke()?;
    }
    tree.resize(tree_account_size())
}
