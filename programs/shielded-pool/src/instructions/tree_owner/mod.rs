//! Tree owners: a tree may name one address that must sign every deposit,
//! transact and merge that writes it. Forester maintenance and protocol
//! administration do not involve the owner.

pub(crate) mod loader;

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use spr_interface::error::ShieldedPoolError;
use spr_tree::TreeAccount;

/// The read-only signer accounts an instruction carries for the owners of its
/// trees. Account parsing finds them by position alone; each tree is checked
/// against them where the instruction loads it, and [`Self::finish`] rejects an
/// account no tree needed. An instruction on unowned trees carries none.
pub(crate) struct TreeOwnerSigners<'a> {
    accounts: &'a [AccountView],
    /// Bit `i` is set once a tree's owner matched `accounts[i]`.
    used: u8,
}

impl<'a> TreeOwnerSigners<'a> {
    pub(crate) fn new(accounts: &'a [AccountView]) -> Result<Self, ProgramError> {
        if accounts.len() > u8::BITS as usize {
            return Err(ShieldedPoolError::TreeOwnerMustSign.into());
        }
        Ok(Self { accounts, used: 0 })
    }

    /// Require the owner of `tree`, when it has one, among the signers.
    pub(crate) fn check(&mut self, tree: &TreeAccount<'_>) -> ProgramResult {
        let Some(owner) = tree.owner() else {
            return Ok(());
        };
        // `new` caps the accounts at `u8::BITS`, so the zip covers all of them
        // and the shift stays in range.
        let bit = self
            .accounts
            .iter()
            .zip(0..u8::BITS)
            .find(|(account, _)| account.is_signer() && account.address().as_array() == &owner)
            .map(|(_, index)| 1u8 << index)
            .ok_or(ShieldedPoolError::TreeOwnerMustSign)?;
        self.used |= bit;
        Ok(())
    }

    /// Call once every tree is checked: each account must have been some
    /// tree's owner. `unexpected_account` is the error the instruction returns
    /// for an account that does not belong in its account list.
    pub(crate) fn finish(&self, unexpected_account: ShieldedPoolError) -> ProgramResult {
        if self.used.count_ones() as usize != self.accounts.len() {
            return Err(unexpected_account.into());
        }
        Ok(())
    }
}
