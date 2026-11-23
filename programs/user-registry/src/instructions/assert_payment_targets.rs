use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_user_registry_interface::{
    instruction::{
        payment_targets_digest, AssertPaymentTargetsData, RegisterData, MAX_PAYMENT_TARGETS,
    },
    UserRecord,
};

use super::common::{check_record_pda_with_bump, SYSTEM_PROGRAM_ID};
use crate::error::{fail, UserRegistryError};

pub fn process_assert_payment_targets(
    program_id: &Address,
    accounts: &[AccountView],
    data: AssertPaymentTargetsData,
) -> ProgramResult {
    if accounts.is_empty() || accounts.len() > MAX_PAYMENT_TARGETS {
        return Err(fail(UserRegistryError::InvalidInstructionData));
    }
    let keys = accounts
        .iter()
        .map(|record| payment_keys(program_id, record))
        .collect::<Result<Vec<_>, _>>()?;
    let targets = accounts
        .iter()
        .zip(&keys)
        .map(|(record, keys)| (record.address().as_array(), keys.as_ref()));
    if payment_targets_digest(targets) != data.digest {
        return Err(fail(UserRegistryError::PaymentTargetChanged));
    }
    Ok(())
}

fn payment_keys(
    program_id: &Address,
    record: &AccountView,
) -> Result<Option<RegisterData>, ProgramError> {
    if record.executable() {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    if record.owned_by(&SYSTEM_PROGRAM_ID) && record.is_data_empty() {
        return Ok(None);
    }
    if !record.owned_by(program_id) {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    let bytes = record.try_borrow()?;
    let state = UserRecord::try_from_account_data(&bytes)
        .map_err(|_| fail(UserRegistryError::InvalidRecordAccount))?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;
    Ok(Some(RegisterData {
        nullifier_pubkey: state.nullifier_pubkey,
        viewing_pubkey: state.viewing_pubkey,
    }))
}
