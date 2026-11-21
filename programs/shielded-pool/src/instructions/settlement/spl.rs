use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use spl_token_2022_interface::{
    extension::{transfer_fee::TransferFeeConfig, BaseStateWithExtensions, PodStateWithExtensions},
    pod::{PodAccount, PodMint},
};
use spr_interface::{
    error::ShieldedPoolError, SHIELDED_POOL_CPI_AUTHORITY_BUMP,
    SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED, SPL_TOKEN_TRANSFER_CHECKED_DISCRIMINATOR,
    SPL_TOKEN_TRANSFER_CHECKED_WITH_FEE_DISCRIMINATOR,
    SPL_TOKEN_TRANSFER_FEE_EXTENSION_DISCRIMINATOR,
};

use super::account::{SplDepositAccounts, SplWithdrawalAccounts};

pub struct SplTransferCpi<'a> {
    pub token_program: &'a AccountView,
    pub from: &'a AccountView,
    pub mint: &'a AccountView,
    pub to: &'a AccountView,
    pub authority: &'a AccountView,
    pub amount: u64,
    pub decimals: u8,
}

impl SplTransferCpi<'_> {
    #[inline(always)]
    pub fn invoke(self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(self, signers: &[Signer]) -> ProgramResult {
        let instruction_accounts = [
            InstructionAccount::writable(self.from.address()),
            InstructionAccount::readonly(self.mint.address()),
            InstructionAccount::writable(self.to.address()),
            InstructionAccount::readonly_signer(self.authority.address()),
        ];
        let mut instruction_data = [0u8; 10];
        instruction_data[0] = SPL_TOKEN_TRANSFER_CHECKED_DISCRIMINATOR;
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());
        instruction_data[9] = self.decimals;
        let instruction = InstructionView {
            program_id: self.token_program.address(),
            accounts: &instruction_accounts,
            data: &instruction_data,
        };
        invoke_signed(
            &instruction,
            &[self.from, self.mint, self.to, self.authority],
            signers,
        )
    }

    /// Token-2022 `TransferCheckedWithFee`: `amount` is the gross debited from
    /// `from`, and the token program fails unless `fee` equals its own fee for
    /// the current epoch.
    fn invoke_with_fee(self, fee: u64) -> ProgramResult {
        let instruction_accounts = [
            InstructionAccount::writable(self.from.address()),
            InstructionAccount::readonly(self.mint.address()),
            InstructionAccount::writable(self.to.address()),
            InstructionAccount::readonly_signer(self.authority.address()),
        ];
        let mut instruction_data = [0u8; 19];
        instruction_data[0] = SPL_TOKEN_TRANSFER_FEE_EXTENSION_DISCRIMINATOR;
        instruction_data[1] = SPL_TOKEN_TRANSFER_CHECKED_WITH_FEE_DISCRIMINATOR;
        instruction_data[2..10].copy_from_slice(&self.amount.to_le_bytes());
        instruction_data[10] = self.decimals;
        instruction_data[11..19].copy_from_slice(&fee.to_le_bytes());
        let instruction = InstructionView {
            program_id: self.token_program.address(),
            accounts: &instruction_accounts,
            data: &instruction_data,
        };
        invoke_signed(
            &instruction,
            &[self.from, self.mint, self.to, self.authority],
            &[],
        )
    }
}

/// Gross amount and fee for a deposit that must credit the vault with exactly
/// `amount`. `None` when the mint has no transfer fee or the current epoch's fee
/// on `amount` is zero, so the deposit keeps the plain `TransferChecked` path.
fn deposit_transfer_fee(
    mint: &AccountView,
    amount: u64,
) -> Result<Option<(u64, u64)>, ProgramError> {
    let data = mint
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    let state = PodStateWithExtensions::<PodMint>::unpack(&data)
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    let Ok(config) = state.get_extension::<TransferFeeConfig>() else {
        return Ok(None);
    };
    let epoch = Clock::get()?.epoch;
    let transfer_fee = config.get_epoch_fee(epoch);
    let gross = transfer_fee
        .calculate_pre_fee_amount(amount)
        .ok_or(ShieldedPoolError::PublicSettlementFailed)?;
    let fee = transfer_fee
        .calculate_fee(gross)
        .ok_or(ShieldedPoolError::PublicSettlementFailed)?;
    if gross.checked_sub(fee) != Some(amount) {
        return Err(ShieldedPoolError::PublicSettlementFailed.into());
    }
    Ok((fee != 0).then_some((gross, fee)))
}

#[inline(never)]
#[profile]
pub fn settle_spl_deposit(settlement: &SplDepositAccounts<'_>, amount: u64) -> ProgramResult {
    let interface_amount_before = token_account_amount(settlement.spl_interface_account)?;
    // A transfer-fee mint withholds its fee in the vault, so the depositor pays
    // the gross that leaves exactly `amount` in the vault's base balance. The
    // check below is unchanged: any other credit still fails.
    match deposit_transfer_fee(settlement.mint_account, amount)? {
        None => SplTransferCpi {
            token_program: settlement.token_program_account,
            from: settlement.user_token_account,
            mint: settlement.mint_account,
            to: settlement.spl_interface_account,
            authority: settlement.token_authority_account,
            amount,
            decimals: settlement.decimals,
        }
        .invoke()?,
        Some((gross, fee)) => SplTransferCpi {
            token_program: settlement.token_program_account,
            from: settlement.user_token_account,
            mint: settlement.mint_account,
            to: settlement.spl_interface_account,
            authority: settlement.token_authority_account,
            amount: gross,
            decimals: settlement.decimals,
        }
        .invoke_with_fee(fee)?,
    }

    let interface_amount_after = token_account_amount(settlement.spl_interface_account)?;
    let expected_interface_amount = interface_amount_before
        .checked_add(amount)
        .ok_or(ShieldedPoolError::PublicSettlementFailed)?;
    if interface_amount_after != expected_interface_amount {
        return Err(ShieldedPoolError::PublicSettlementFailed.into());
    }

    Ok(())
}

#[inline(never)]
#[profile]
pub fn settle_spl_withdrawal(settlement: &SplWithdrawalAccounts<'_>, amount: u64) -> ProgramResult {
    let bump = [SHIELDED_POOL_CPI_AUTHORITY_BUMP];
    let seeds = [
        Seed::from(SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    SplTransferCpi {
        token_program: settlement.token_program_account,
        from: settlement.spl_interface_account,
        mint: settlement.mint_account,
        to: settlement.user_token_account,
        authority: settlement.cpi_authority_account,
        amount,
        decimals: settlement.decimals,
    }
    .invoke_signed(core::slice::from_ref(&signer))
}

/// Read the transferable base balance. Token-2022 extension balances such as
/// `withheld_amount` deliberately do not count as vault collateral.
fn token_account_amount(account: &AccountView) -> Result<u64, ProgramError> {
    let data = account
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    let state = PodStateWithExtensions::<PodAccount>::unpack(&data)
        .map_err(caused_by(ShieldedPoolError::PublicSettlementFailed))?;
    Ok(u64::from(state.base.amount))
}
