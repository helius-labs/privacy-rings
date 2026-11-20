//! Every vector of `test-vectors/transact_functional.json` that runs on the
//! default ring, settled as a top-level Shielded Pool `transact` with the
//! hidden owner authorizing inside the proof.
//!
//! Requires the `proofs` feature and `just build-test-programs build-prover-server build-cli`.
//! Every test proves through the one shared prover, which refuses concurrent
//! proofs, so run the binary with `--test-threads 1` as
//! `just test-program-proofs-programs-only` does.

use shielded_pool_tests::support::functional_vectors::VectorRun;
use spr_test_utils::functional_vectors::{committed_file, committed_vector};

macro_rules! default_ring_vectors {
    ($($name:ident),* $(,)?) => {
        const DEFAULT_RING_VECTORS: &[&str] = &[$(stringify!($name)),*];
        $(
            #[test]
            fn $name() {
                let vector = committed_vector(stringify!($name)).expect("committed vector");
                VectorRun { vector: &vector }
                    .execute()
                    .unwrap_or_else(|error| panic!("{error:#}"));
            }
        )*
    };
}

default_ring_vectors!(
    // A: ownership and authorization
    hidden_ring_note,
    hidden_two_notes,
    no_signers,
    hidden_then_signer,
    signer_then_hidden,
    two_signers,
    three_signers,
    fee_payer_is_co_owner,
    co_owner_receives_payment,
    co_owner_only_contributes,
    // B: outputs and recipients
    recipient_outputs_without_data,
    self_transfer,
    two_recipients_and_change,
    zero_amount_output,
    exact_spend_no_change,
    // C: padding
    compact_input_padding,
    non_compact_dummy_input,
    compact_outputs,
    trailing_dummy_outputs,
    dummy_output_tags,
    // D: public value
    public_deposit,
    public_withdrawal,
    full_withdrawal,
    two_withdrawal_legs_one_asset,
    spl_deposit,
    spl_withdrawal,
    token_2022_deposit_and_withdrawal,
    three_public_slots,
    deposit_and_withdrawal_of_different_assets,
    // E: assets
    multi_asset_private,
    sol_and_spl_private,
    one_asset_many_note_sizes,
    // F: address slots
    hidden_address_then_hidden_note,
    signer_address_then_hidden_note,
    hidden_address_only_with_deposit,
    // G: data-bearing notes
    signer_owned_data_output,
    hidden_owned_data_output,
    spend_note_with_data_hash,
    // H: trees
    inputs_across_two_trees,
    equal_notes_in_two_trees,
    output_to_other_tree,
    cached_input_beside_state_input,
    cached_input_only,
    // I: shapes
    widest_common_inputs,
    widest_common_outputs,
    eight_inputs_eight_outputs,
    one_input_sixteen_outputs,
    forty_eight_inputs,
    // K: several transactions
    second_payment_to_same_recipient,
    recipient_spends_back,
    change_chain,
);

/// The list above is the catalog's default-ring `run` set, no more and no less.
#[test]
fn every_default_ring_vector_has_a_test() {
    let mut runnable: Vec<String> = committed_file()
        .expect("committed catalog")
        .vectors
        .into_iter()
        .filter(|vector| vector.rings.default.is_run())
        .map(|vector| vector.name)
        .collect();
    runnable.sort();
    let mut listed: Vec<String> = DEFAULT_RING_VECTORS
        .iter()
        .map(|name| name.to_string())
        .collect();
    listed.sort();
    assert_eq!(listed, runnable);
}
