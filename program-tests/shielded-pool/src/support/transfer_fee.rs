//! Token-2022 transfer-fee mint fixtures.
//!
//! A deposit of a transfer-fee mint debits the depositor the gross amount
//! whose fee leaves exactly the nominal amount in the vault's base balance; the
//! fee stays withheld in the vault until anyone harvests it to the mint.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{
        transfer_fee::{
            instruction::initialize_transfer_fee_config, TransferFee, TransferFeeAmount,
            TransferFeeConfig,
        },
        BaseStateWithExtensions, ExtensionType, PodStateWithExtensions,
    },
    instruction::{initialize_account3, initialize_mint2},
    pod::{PodAccount, PodMint},
};
use spr_program_test::{system_create_account_ix, SprProgramTest};

/// Create a Token-2022 mint with `TransferFeeConfig`, the payer as mint, fee
/// config and withdraw-withheld authority, 9 decimals.
pub fn create_transfer_fee_mint(
    rpc: &mut SprProgramTest,
    transfer_fee_basis_points: u16,
    maximum_fee: u64,
) -> Pubkey {
    let token_program = SprProgramTest::token_2022_program_id();
    let mint = Keypair::new();
    let mint_len =
        ExtensionType::try_calculate_account_len::<PodMint>(&[ExtensionType::TransferFeeConfig])
            .expect("transfer-fee mint length");
    let payer = rpc.payer.insecure_clone();
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &mint.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(mint_len),
        mint_len as u64,
        &token_program,
    );
    let init_fee_ix = initialize_transfer_fee_config(
        &token_program,
        &mint.pubkey(),
        Some(&payer.pubkey()),
        Some(&payer.pubkey()),
        transfer_fee_basis_points,
        maximum_fee,
    )
    .expect("initialize transfer fee config");
    let init_mint_ix = initialize_mint2(&token_program, &mint.pubkey(), &payer.pubkey(), None, 9)
        .expect("initialize transfer-fee mint");

    rpc.create_and_send_default_payer_transaction(
        &[create_ix, init_fee_ix, init_mint_ix],
        &[&mint],
    )
    .expect("create transfer-fee mint");
    mint.pubkey()
}

/// Create a Token-2022 token account of a transfer-fee mint.
pub fn create_transfer_fee_token_account(
    rpc: &mut SprProgramTest,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    let token_program = SprProgramTest::token_2022_program_id();
    let account = Keypair::new();
    let account_len =
        ExtensionType::try_calculate_account_len::<PodAccount>(&[ExtensionType::TransferFeeAmount])
            .expect("transfer-fee token-account length");
    let create_ix = system_create_account_ix(
        &rpc.payer.pubkey(),
        &account.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(account_len),
        account_len as u64,
        &token_program,
    );
    let init_ix = initialize_account3(&token_program, &account.pubkey(), mint, owner)
        .expect("initialize transfer-fee token account");

    rpc.create_and_send_default_payer_transaction(&[create_ix, init_ix], &[&account])
        .expect("create transfer-fee token account");
    account.pubkey()
}

/// The fee a mint charges in `epoch`.
pub fn epoch_fee(rpc: &SprProgramTest, mint: &Pubkey, epoch: u64) -> TransferFee {
    let data = rpc.account_data(mint).expect("mint account");
    let state = PodStateWithExtensions::<PodMint>::unpack(&data).expect("unpack mint");
    *state
        .get_extension::<TransferFeeConfig>()
        .expect("transfer fee config")
        .get_epoch_fee(epoch)
}

/// Withheld fee tokens held by a token account.
pub fn account_withheld(rpc: &SprProgramTest, account: &Pubkey) -> u64 {
    let data = rpc.account_data(account).expect("token account");
    let state = PodStateWithExtensions::<PodAccount>::unpack(&data).expect("unpack account");
    u64::from(
        state
            .get_extension::<TransferFeeAmount>()
            .expect("transfer fee amount")
            .withheld_amount,
    )
}

/// Withheld fee tokens harvested to a mint.
pub fn mint_withheld(rpc: &SprProgramTest, mint: &Pubkey) -> u64 {
    let data = rpc.account_data(mint).expect("mint account");
    let state = PodStateWithExtensions::<PodMint>::unpack(&data).expect("unpack mint");
    u64::from(
        state
            .get_extension::<TransferFeeConfig>()
            .expect("transfer fee config")
            .withheld_amount,
    )
}
