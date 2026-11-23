use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_user_registry_interface::{instruction::AssertPaymentTargetData, UserRecord};

use super::common::{check_record_pda, SYSTEM_PROGRAM_ID};
use crate::error::{fail, UserRegistryError};

pub fn process_assert_payment_target(
    program_id: &Address,
    accounts: &[AccountView],
    data: AssertPaymentTargetData,
) -> ProgramResult {
    let [record] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    let owner = Address::new_from_array(data.owner);
    let bump = check_record_pda(record, &owner, program_id)?;
    let Some(keys) = data.expected_keys else {
        return if record.owned_by(&SYSTEM_PROGRAM_ID)
            && record.is_data_empty()
            && !record.executable()
        {
            Ok(())
        } else {
            Err(fail(UserRegistryError::PaymentTargetChanged))
        };
    };
    if !record.owned_by(program_id) {
        return Err(fail(UserRegistryError::PaymentTargetChanged));
    }
    let bytes = record.try_borrow()?;
    let state = UserRecord::try_from_account_data(&bytes)
        .map_err(|_| fail(UserRegistryError::InvalidRecordAccount))?;
    if state.owner.as_array() != owner.as_array() || state.bump != bump {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    if state.nullifier_pubkey != keys.nullifier_pubkey
        || state.viewing_pubkey != keys.viewing_pubkey
    {
        return Err(fail(UserRegistryError::PaymentTargetChanged));
    }
    Ok(())
}
