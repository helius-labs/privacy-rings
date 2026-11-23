mod common;

use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use spr_user_registry::error::UserRegistryError;
use spr_user_registry_interface::{
    instruction::{assert_payment_targets, PaymentTarget, RegisterData},
    user_record_pda, MergeEncryptionScheme,
};
use user_registry_tests::{
    build_register_ix, build_set_merge_encryption_ix, build_update_keys_ix, UserRegistryTestRig,
};

use common::{funded_keypair, keys, register, Keys};

fn expected(owner: Pubkey, keys: Keys) -> Instruction {
    assert_payment_targets(&[PaymentTarget {
        owner: owner.to_bytes(),
        keys: Some(RegisterData {
            nullifier_pubkey: keys.nullifier,
            viewing_pubkey: keys.viewing,
        }),
    }])
    .unwrap()
}

fn missing(owner: Pubkey) -> Instruction {
    assert_payment_targets(&[PaymentTarget {
        owner: owner.to_bytes(),
        keys: None,
    }])
    .unwrap()
}

fn program_error(index: u8, error: UserRegistryError) -> TransactionError {
    TransactionError::InstructionError(index, InstructionError::Custom(error as u32))
}

#[test]
fn service_route_accepts_absence_and_rejects_a_new_registration() {
    let mut rig = UserRegistryTestRig::new();
    let owner = Keypair::new();
    let address = owner.pubkey();
    let unregistered = missing(address);
    let value = keys(1);
    rig.send(unregistered.clone(), &[]).expect("absent PDA");
    rig.fund(&user_record_pda(&address).0, 1_000_000);
    rig.send(unregistered.clone(), &[]).expect("prefunded PDA");
    assert_eq!(
        rig.send(expected(address, value), &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    rig.fund(&address, common::OWNER_LAMPORTS);
    register(&mut rig, &owner, value);
    assert_eq!(
        rig.send(unregistered, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
}

#[test]
fn registered_route_requires_both_keys_but_ignores_the_merge_setting() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let address = owner.pubkey();
    let before = keys(2);
    let after = Keys {
        viewing: keys(3).viewing,
        ..before
    };
    register(&mut rig, &owner, before);
    let original = expected(address, before);
    rig.send(original.clone(), &[]).expect("current keys");
    rig.send(
        build_set_merge_encryption_ix(&address, &address, MergeEncryptionScheme::PoseidonCtrV1),
        &[&owner],
    )
    .unwrap();
    rig.send(original.clone(), &[]).expect("same payment keys");
    rig.send(build_update_keys_ix(&address, after.viewing), &[&owner])
        .unwrap();
    assert_eq!(
        rig.send(original, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    let wrong_nullifier = Keys {
        nullifier: keys(4).nullifier,
        ..after
    };
    assert_eq!(
        rig.send(expected(address, wrong_nullifier), &[])
            .unwrap_err()
            .err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    rig.send(expected(address, after), &[])
        .expect("rotated keys");
}

#[test]
fn stale_target_rolls_back_another_instruction_in_the_same_transaction() {
    let mut rig = UserRegistryTestRig::new();
    let recipient = funded_keypair(&mut rig);
    let other = funded_keypair(&mut rig);
    let value = keys(5);
    register(&mut rig, &recipient, value);
    let other_record = user_record_pda(&other.pubkey()).0;
    let write = build_register_ix(&other.pubkey(), value.nullifier, value.viewing);
    let stale = missing(recipient.pubkey());
    let failure = rig
        .send_all(&[write.clone(), stale], &[&other])
        .unwrap_err();
    assert_eq!(
        failure.err,
        program_error(1, UserRegistryError::PaymentTargetChanged)
    );
    assert!(rig.svm.get_account(&other_record).is_none());
    rig.send_all(&[write, expected(recipient.pubkey(), value)], &[&other])
        .expect("matching assertion permits the atomic write");
    assert!(rig.svm.get_account(&other_record).is_some());
}

#[test]
fn assertion_requires_the_canonical_pda_and_valid_record_data() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let address = owner.pubkey();
    let value = keys(6);
    register(&mut rig, &owner, value);
    let absent = Keypair::new();
    let mut spoofed = missing(address);
    spoofed.accounts[0].pubkey = user_record_pda(&absent.pubkey()).0;
    assert_eq!(
        rig.send(spoofed, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    let record_address = user_record_pda(&address).0;
    let mut invalid = rig.svm.get_account(&record_address).unwrap();
    invalid.data[0] ^= 1;
    rig.svm.set_account(record_address, invalid).unwrap();
    assert_eq!(
        rig.send(expected(address, value), &[]).unwrap_err().err,
        program_error(0, UserRegistryError::InvalidRecordAccount),
    );
}

#[test]
fn mixed_batch_binds_record_order_and_requires_an_exact_digest() {
    let mut rig = UserRegistryTestRig::new();
    let first = funded_keypair(&mut rig);
    let second = Keypair::new();
    let third = funded_keypair(&mut rig);
    let original = keys(7);
    register(&mut rig, &first, original);
    register(&mut rig, &third, original);
    let registered = |owner: Pubkey| PaymentTarget {
        owner: owner.to_bytes(),
        keys: Some(RegisterData {
            nullifier_pubkey: original.nullifier,
            viewing_pubkey: original.viewing,
        }),
    };
    let instruction = assert_payment_targets(&[
        registered(first.pubkey()),
        PaymentTarget {
            owner: second.pubkey().to_bytes(),
            keys: None,
        },
        registered(third.pubkey()),
    ])
    .unwrap();
    rig.send(instruction.clone(), &[]).expect("ordered batch");
    let mut reordered = instruction.clone();
    reordered.accounts.swap(0, 2);
    assert_eq!(
        rig.send(reordered, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    let mut wrong_digest = instruction.clone();
    wrong_digest.data[1] ^= 1;
    assert_eq!(
        rig.send(wrong_digest, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::PaymentTargetChanged),
    );
    let mut extra = instruction;
    extra.data.push(0);
    assert_eq!(
        rig.send(extra, &[]).unwrap_err().err,
        program_error(0, UserRegistryError::InvalidInstructionData),
    );
}
