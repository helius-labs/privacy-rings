//! Deposits of Token-2022 transfer-fee mints credit the vault with exactly the
//! nominal amount: the program debits the depositor the gross whose current
//! epoch fee leaves `amount` in the vault, through `TransferCheckedWithFee`.
//! The fee stays withheld in the vault and is harvestable by anyone.

use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_token_2022_interface::extension::transfer_fee::instruction::{
    harvest_withheld_tokens_to_mint, withdraw_withheld_tokens_from_mint,
};
use spr_program_test::SprProgramTest;

use shielded_pool_tests::support::{
    fixtures::Pool,
    transfer_fee::{
        account_withheld, create_transfer_fee_mint, create_transfer_fee_token_account, epoch_fee,
        mint_withheld,
    },
};

struct FeeDeposit {
    pool: Pool,
    mint: Pubkey,
    vault: Pubkey,
    source: Pubkey,
}

/// A pool with a registered transfer-fee mint and a depositor holding `funded`.
fn fee_deposit_env(basis_points: u16, maximum_fee: u64, funded: u64) -> (FeeDeposit, Keypair) {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let token_program = SprProgramTest::token_2022_program_id();
    let mint = create_transfer_fee_mint(&mut pool.rpc, basis_points, maximum_fee);
    let (_, vault) = pool
        .rpc
        .create_spl_interface_with_program(&pool.authority, &mint, token_program)
        .expect("create transfer-fee interface");
    let depositor = pool.funded_signer(1_000_000_000);
    let source = create_transfer_fee_token_account(&mut pool.rpc, &mint, &depositor.pubkey());
    pool.rpc
        .mint_to_with_program(&mint, &source, funded, token_program)
        .expect("mint Token-2022 balance");
    (
        FeeDeposit {
            pool,
            mint,
            vault,
            source,
        },
        depositor,
    )
}

/// Deposit `amount` and assert: the vault's base balance rises by exactly
/// `amount`, the depositor pays `expected_gross`, and the vault withholds the
/// difference. Returns the env for further checks.
fn deposit_credits_nominal(
    basis_points: u16,
    maximum_fee: u64,
    amount: u64,
    expected_gross: u64,
) -> FeeDeposit {
    let funded = expected_gross + 1_000;
    let (mut env, depositor) = fee_deposit_env(basis_points, maximum_fee, funded);
    let epoch = env.pool.rpc.svm.get_sysvar::<Clock>().epoch;
    let fee = epoch_fee(&env.pool.rpc, &env.mint, epoch);
    // The test's expectation agrees with Token-2022's own inverse.
    assert_eq!(fee.calculate_pre_fee_amount(amount), Some(expected_gross));
    assert_eq!(fee.calculate_post_fee_amount(expected_gross), Some(amount));

    let data = SprProgramTest::spl_shield_data_with_program(
        amount,
        [1u8; 32],
        &env.mint,
        &env.source,
        SprProgramTest::token_2022_program_id(),
    );
    let tree = env.pool.tree;
    let root_before = env.pool.rpc.state_root(&tree).expect("root");
    let event = env
        .pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("transfer-fee deposit");

    assert_eq!(
        event.output.amount, amount,
        "the note carries the nominal amount"
    );
    assert_eq!(env.pool.rpc.token_balance(&env.vault), Some(amount));
    assert_eq!(
        env.pool.rpc.token_balance(&env.source),
        Some(funded - expected_gross)
    );
    assert_eq!(
        account_withheld(&env.pool.rpc, &env.vault),
        expected_gross - amount
    );
    assert_ne!(env.pool.rpc.state_root(&tree), Some(root_before));
    env
}

#[test]
fn one_percent_fee_deposit_credits_the_nominal_amount() {
    // gross 405: ceil(405 * 1%) = 5, 405 - 5 = 400.
    deposit_credits_nominal(100, u64::MAX, 400, 405);
}

#[test]
fn five_percent_fee_deposit_credits_the_nominal_amount() {
    // gross 1_052_632: ceil(1_052_632 * 5%) = 52_632.
    deposit_credits_nominal(500, u64::MAX, 1_000_000, 1_052_632);
}

#[test]
fn capped_fee_deposit_pays_only_the_maximum_fee() {
    // 5% of 1_000_000 is above the 10 token cap, so the fee is the cap.
    deposit_credits_nominal(500, 10, 1_000_000, 1_000_010);
}

#[test]
fn hundred_percent_capped_fee_deposit_pays_amount_plus_cap() {
    deposit_credits_nominal(10_000, 25, 400, 425);
}

#[test]
fn zero_fee_transfer_fee_mint_deposit_withholds_nothing() {
    deposit_credits_nominal(0, u64::MAX, 400, 400);
}

#[test]
fn withheld_deposit_fee_is_harvestable_by_anyone() {
    let mut env = deposit_credits_nominal(100, u64::MAX, 400, 405);
    let token_program = SprProgramTest::token_2022_program_id();

    // Harvesting needs no signature from the vault's owner: any fee payer
    // moves the withheld fee from the vault to the mint.
    let stranger = env.pool.funded_signer(1_000_000_000);
    let harvest = harvest_withheld_tokens_to_mint(&token_program, &env.mint, &[&env.vault])
        .expect("harvest instruction");
    env.pool
        .rpc
        .create_and_send_transaction(&[harvest], &stranger.pubkey(), &[&stranger as &dyn Signer])
        .expect("permissionless harvest");
    assert_eq!(account_withheld(&env.pool.rpc, &env.vault), 0);
    assert_eq!(mint_withheld(&env.pool.rpc, &env.mint), 5);
    assert_eq!(
        env.pool.rpc.token_balance(&env.vault),
        Some(400),
        "harvest leaves the vault's collateral untouched"
    );

    // The mint's withdraw-withheld authority then collects it.
    let payer = env.pool.rpc.payer.insecure_clone();
    let receiver = create_transfer_fee_token_account(&mut env.pool.rpc, &env.mint, &payer.pubkey());
    let withdraw = withdraw_withheld_tokens_from_mint(
        &token_program,
        &env.mint,
        &receiver,
        &payer.pubkey(),
        &[],
    )
    .expect("withdraw withheld instruction");
    env.pool
        .rpc
        .create_and_send_default_payer_transaction(&[withdraw], &[])
        .expect("withdraw withheld from mint");
    assert_eq!(env.pool.rpc.token_balance(&receiver), Some(5));
    assert_eq!(mint_withheld(&env.pool.rpc, &env.mint), 0);
}
