use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_user_registry_interface::instruction::{
    discriminator, AssertPaymentTargetsData, RegisterData, SetMergeEncryptionData, UpdateKeysData,
};

use crate::{
    error::{fail, UserRegistryError},
    instructions::{
        assert_payment_targets::process_assert_payment_targets, register::process_register,
        set_merge_encryption::process_set_merge_encryption, update_keys::process_update_keys,
    },
};

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_discriminator, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_discriminator {
        discriminator::REGISTER => {
            let data = RegisterData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_register(program_id, accounts, data)
        }
        discriminator::SET_MERGE_ENCRYPTION => {
            let data = SetMergeEncryptionData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_set_merge_encryption(program_id, accounts, data)
        }
        discriminator::UPDATE_KEYS => {
            let data = UpdateKeysData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_update_keys(program_id, accounts, data)
        }
        discriminator::ASSERT_PAYMENT_TARGETS => {
            let data = AssertPaymentTargetsData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_assert_payment_targets(program_id, accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
