use shielded_pool_tests::support::transact::{current_tree_roots, proof_env, Pool};
use spr_interface::state::cache::empty_cached_input_fields;

use num_bigint::BigUint;
use solana_account::Account;
use solana_clock::Clock;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_client::{
    BatchAddressAppendInputs, ComputeBudgetConfig, ProofCompressed, ProverClient, ProverExt,
    PublicInputs, PublicTransfers, STATE_TREE_HEIGHT,
};
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::solana_owner_identity, Poseidon,
};
use spr_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::TransactIxData,
    pda,
    state::{read_tree_id, TreeFeeSchedule, NULLIFIER_TREE_HEIGHT},
    NullifierPda,
};
use spr_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use spr_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use spr_program::instruction::Transact;
use spr_program_test::{ProgramTestError, Rejection, Rpc, TransactionTrace};
use spr_protocol_instructions::{BatchUpdateNullifierTree, CloseNullifierPdas};
use spr_test_utils::{
    nullifier_pda::{
        assert_nullifier_pda, assert_nullifier_pdas, assert_nullifier_pdas_absent,
        assert_tree_lamports_after_spend, nullifier_pda_addresses, nullifier_pda_rent,
        nullifier_queue_next_index, tree_close_before_index, tree_fee_for_spend, tree_fees,
        tree_fees_from, tree_id,
    },
    transact::{
        build_transfer_prover_inputs, change_and_dummy_outputs,
        derive_test_transfer_output_blindings, dummy_input, external_data_hash, fe, inline_outputs,
        input_utxo, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
        prove_and_verify_transfer, set_output_owner_tags, single_tree_slots, sol_public_slots,
        test_private_tx_blinding, transfer_input, tree_contexts, TransferInputArgs,
        TransferProverInputsArgs, TEST_BLINDING_SEED,
    },
};
use spr_transaction::{instructions::transact::PrivateTxHash, SOL_MINT};
use spr_tree::{
    nullifier_tree::{
        batch::CachedTreeUpdate, constants::NULLIFIER_TREE_ZKP_BATCHES, layout::NullifierTreeLayout,
    },
    NullifierTreeInitParams, TreeAccount,
};

const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

fn proof_env_with_fee(fee_per_tree: u64) -> Pool {
    let mut env = proof_env();
    let authority = env.authority.insecure_clone();
    env.rpc
        .set_tree_fees(
            &authority,
            &env.tree,
            TreeFeeSchedule {
                fee_per_tree,
                ..TreeFeeSchedule::default()
            },
        )
        .expect("set nullifier fee");
    env
}

fn build_valid_transact_ix(env: &mut Pool) -> TransactIxData {
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    build_transact_ix(env, &nf_tree, 0)
}

/// A real 2x2 transact spending a fresh zero-amount deposit, with both
/// nullifiers proven absent from `nf_tree`, whose root must be the on-chain
/// nullifier root at `nullifier_root_index`.
fn build_transact_ix(
    env: &mut Pool,
    nf_tree: &NullifierTree,
    nullifier_root_index: u16,
) -> TransactIxData {
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let owner_pk_hash = owner_public_key
        .owner_proof_input_hash()
        .expect("owner pk hash");
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let event = env
        .rpc
        .deposit_sol(&env.tree, &payer, 0, owner_field)
        .expect("proofless zero deposit");
    let utxo = env
        .rpc
        .indexed_deposit_utxo(&event, owner_public_key)
        .expect("indexed deposit UTXO");
    let blinding = utxo.blinding;
    assert_eq!((utxo.asset.asset, utxo.amount), (SOL_MINT, 0));

    let tree_id = env.tree_id;
    let utxo_hash = utxo
        .hash(&nullifier_pk, &zero, &zero, tree_id)
        .expect("utxo hash");
    let (utxo_root_index, utxo_root, _) = current_tree_roots(&env.rpc, &env.tree);
    let nullifier_root = nullifier_root_at(env, nullifier_root_index).expect("nullifier root");
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");

    let tree_slots = single_tree_slots(tree_id, utxo_root, nullifier_root);
    let (dummy, dummy_nullifier) = dummy_input(&[2u8; 31], nf_tree, tree_id).expect("dummy input");
    let real_input = transfer_input(TransferInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        tree_id,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    // Slot 0 is a real zero-amount change output owned by the payer and slots
    // 1-2 are dummies naming it, as a wallet builds a spend with no change.
    // The payer owns the input, so the instruction lists it as an owner signer.
    let change_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let change_nullifier_pk = change_nullifier_key
        .pubkey()
        .expect("change output nullifier pubkey");
    let mut outputs = change_and_dummy_outputs(
        utxo.owner,
        change_nullifier_pk,
        [1u8; 31],
        &[[2u8; 31]],
        tree_id,
    )
    .expect("change and dummy outputs");
    let output_hashes = derive_test_transfer_output_blindings(&nullifier, &mut outputs)
        .expect("derive output blindings");

    let mut transact_ix_data = new_transact_ix_data(
        vec![input_utxo(nullifier), input_utxo(dummy_nullifier)],
        utxo_root_index,
        Vec::new(),
        inline_outputs(&output_hashes, &[payer_bytes; 2]),
    );
    transact_ix_data.tree_contexts = tree_contexts(&[(utxo_root_index, nullifier_root_index)]);
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[change_nullifier_pk, zero]);

    let external_hash = external_data_hash(&transact_ix_data, &[]).expect("external data hash");
    let private_tx_blinding = test_private_tx_blinding(&nullifier).expect("private tx blinding");
    let change_output_hash = *output_hashes.first().expect("change output hash");
    let private_tx = PrivateTxHash::new(
        &[utxo_hash, zero],
        &[change_output_hash, zero],
        &private_tx_blinding,
    )
    .hash()
    .expect("private tx hash");
    let signer_hashes = [
        solana_owner_identity(&payer_bytes).expect("payer identity"),
        zero,
        zero,
    ];
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_input_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        tree_slots: &tree_slots,
        output_tree_id: tree_id,
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        input_flags: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
        cached_inputs: empty_cached_input_fields(2).expect("cache selection"),
    }
    .hash()
    .expect("public input hash");

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy],
        outputs,
        tree_slots,
        output_tree_id: tree_id,
        blinding_seed: TEST_BLINDING_SEED,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "transact")
            .expect("prove transact");
    transact_ix_data.private_tx_hash = private_tx;
    transact_ix_data
}

fn transact_instruction(env: &Pool, data: TransactIxData) -> solana_instruction::Instruction {
    Transact {
        payer: env.rpc.payer.pubkey(),
        input_trees: vec![env.tree],
        output_tree: env.tree,
        owner_signers: vec![env.rpc.payer.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}

fn nullifiers_of(data: &TransactIxData) -> Vec<[u8; 32]> {
    data.inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect()
}

fn tree_account(env: &Pool) -> Account {
    env.rpc.svm.get_account(&env.tree).expect("tree account")
}

fn live_nullifier_pdas(tree: &Account) -> u64 {
    let mut data = tree.data.clone();
    let live = TreeAccount::from_bytes(&mut data, [0u8; 32])
        .expect("tree layout")
        .live_nullifier_pdas();
    live
}

fn payer_lamports(env: &Pool) -> u64 {
    env.rpc
        .svm
        .get_account(&env.rpc.payer.pubkey())
        .expect("payer account")
        .lamports
}

#[track_caller]
fn assert_transact_frame(env: &Pool, trace: &TransactionTrace, nullifiers: &[[u8; 32]]) {
    let tree = env.tree;
    let payer = env.rpc.payer.pubkey();
    let mut changed: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .collect();
    changed.sort();
    let mut expected: Vec<Pubkey> = nullifier_pda_addresses(&tree, nullifiers)
        .into_iter()
        .chain([tree, payer])
        .collect();
    expected.sort();
    assert_eq!(
        changed, expected,
        "transact changes only the payer, the tree and the new nullifier PDAs"
    );
    let forester_fee = tree_fee_for_spend(&tree_account(env), &tree).expect("forester fee");
    let system_invocations = trace
        .logs
        .iter()
        .filter(|line| line.as_str() == "Program 11111111111111111111111111111111 invoke [2]")
        .count();
    assert_eq!(
        system_invocations,
        nullifiers.len() + usize::from(forester_fee != 0),
        "one CPI per nullifier, plus one transfer only when the tree charges a fee"
    );
}

#[test]
fn transact_creates_one_nullifier_pda_per_input() {
    assert_creates_nullifier_pdas(0);
}

#[test]
fn transact_collects_fee_with_unfunded_nullifier_pdas() {
    assert_creates_nullifier_pdas(123);
}

fn assert_creates_nullifier_pdas(fee_per_tree: u64) {
    let mut env = proof_env_with_fee(fee_per_tree);
    let tree = env.tree;
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");
    let tree_before = tree_account(&env);
    let payer_before = payer_lamports(&env);

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect("transact with a valid proof");

    for (nullifier, offset) in nullifiers.iter().zip(0..) {
        assert_nullifier_pda(&env.rpc, &tree, nullifier, queue_next_before + offset)
            .expect("nullifier PDA stores its queue index and canonical bump");
    }
    assert_tree_lamports_after_spend(&env.rpc, &tree, &tree_before, nullifiers.len() as u64)
        .expect("tree lamports");
    let forester_fee = tree_fee_for_spend(&tree_before, &tree).expect("forester fee");
    assert_eq!(
        payer_before,
        payer_lamports(&env) + LAMPORTS_PER_SIGNATURE + forester_fee,
        "payer pays the transaction fee and the forester fee; nullifier PDA rent comes from the tree"
    );
    let (fees_before, fee_balance_before) =
        tree_fees_from(&tree_before, &tree).expect("tree fees before");
    assert_eq!(
        tree_fees(&env.rpc, &tree).expect("tree fees after"),
        (fees_before, fee_balance_before + forester_fee),
        "transact credits exactly the collected fee to the fee balance"
    );
    assert_eq!(
        live_nullifier_pdas(&tree_account(&env)),
        live_nullifier_pdas(&tree_before) + nullifiers.len() as u64,
        "transact counts every nullifier PDA it opens"
    );
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("transact trace")
        .clone();
    assert_transact_frame(&env, &trace, &nullifiers);
}

#[test]
fn transact_rejects_a_nullifier_queued_by_an_earlier_transaction() {
    let mut env = proof_env();
    let tree = env.tree;
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data.clone())], &[])
        .expect("first spend");
    let tree_after_first = tree_account(&env);

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect_err("replaying a queued nullifier must be rejected");
    Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("replay trace")
        .assert_rolled_back_except(&[env.rpc.payer.pubkey()]);
    assert_eq!(
        tree_account(&env),
        tree_after_first,
        "rejected replay leaves the tree untouched"
    );
    for (nullifier, offset) in nullifiers.iter().zip(0..) {
        assert_nullifier_pda(&env.rpc, &tree, nullifier, queue_next_before + offset)
            .expect("first spend's nullifier PDA unchanged");
    }
}

#[test]
fn transact_tops_up_prefunded_nullifier_pdas() {
    assert_tops_up_prefunded_nullifier_pdas(0);
}

#[test]
fn transact_collects_fee_with_prefunded_nullifier_pdas() {
    assert_tops_up_prefunded_nullifier_pdas(123);
}

fn assert_tops_up_prefunded_nullifier_pdas(fee_per_tree: u64) {
    let mut env = proof_env_with_fee(fee_per_tree);
    let tree = env.tree;
    let payer = env.rpc.payer.pubkey();
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let nullifier_pdas = nullifier_pda_addresses(&tree, &nullifiers);
    let rent = nullifier_pda_rent(&env.rpc).expect("nullifier PDA rent");
    let underfunded = env
        .rpc
        .get_minimum_balance_for_rent_exemption(0)
        .expect("empty account rent");
    assert!(
        underfunded < rent,
        "the smallest rent-exempt donation must stay below the nullifier PDA rent"
    );
    let overfunded = rent + 1_000;
    let prefunds = [underfunded, overfunded];
    for (nullifier_pda, prefund) in nullifier_pdas.iter().zip(prefunds) {
        env.rpc
            .create_and_send_default_payer_transaction(
                &[solana_system_interface::instruction::transfer(
                    &payer,
                    nullifier_pda,
                    prefund,
                )],
                &[],
            )
            .expect("prefund nullifier PDA");
    }
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");
    let tree_before = tree_account(&env);
    let payer_before = payer_lamports(&env);

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect("transact with prefunded nullifier PDAs");

    let (first_nullifier, second_nullifier) = match nullifiers.as_slice() {
        [first, second] => (first, second),
        other => panic!("expected two nullifiers, got {other:?}"),
    };
    assert_nullifier_pda(&env.rpc, &tree, first_nullifier, queue_next_before)
        .expect("underfunded nullifier PDA topped up to exactly its rent");
    let (overfunded_nullifier_pda, _) = pda::nullifier_pda(&tree, second_nullifier);
    let overfunded_account = env
        .rpc
        .svm
        .get_account(&overfunded_nullifier_pda)
        .expect("overfunded nullifier PDA account");
    let expected_overfunded = Account {
        lamports: overfunded,
        data: NullifierPda {
            queue_index: queue_next_before + 1,
            tree_id: tree_id(&env.rpc, &tree).expect("tree id"),
        }
        .to_account_data()
        .to_vec(),
        owner: pda::shielded_pool_program_id(),
        executable: false,
        rent_epoch: overfunded_account.rent_epoch,
    };
    assert_eq!(
        overfunded_account, expected_overfunded,
        "overfunded nullifier PDA keeps its surplus and is initialized in place"
    );

    let forester_fee = tree_fee_for_spend(&tree_before, &tree).expect("forester fee");
    let tree_after = tree_account(&env);
    assert_eq!(
        (
            tree_after.lamports,
            tree_after.owner,
            tree_after.data.len(),
            tree_after.executable,
        ),
        (
            tree_before.lamports + forester_fee - (rent - underfunded),
            tree_before.owner,
            tree_before.data.len(),
            tree_before.executable,
        ),
        "tree funds only the missing rent of the underfunded nullifier PDA"
    );
    assert_eq!(
        payer_before,
        payer_lamports(&env) + LAMPORTS_PER_SIGNATURE + forester_fee,
        "payer pays the transaction fee and the forester fee"
    );
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("transact trace")
        .clone();
    assert_transact_frame(&env, &trace, &nullifiers);
}

// Nullifier-PDA close boundary.
//
// A closed nullifier PDA no longer stops a second spend of its nullifier; only
// the root history does. So a PDA may close only once no accepted nullifier
// root predates its nullifier's insertion. The queue batch equals the root
// history window (100 zkp batches, 100 roots), and the close watermark moves
// to a batch's start only when the batch after it is fully inserted.
//
// The test puts the spent nullifier at the tightest spot: the last zkp batch of
// queue batch 0. Its pre-insertion root then lives in the history until update
// 199 and the watermark lets the PDA close at update 200, a margin of one
// update. The tree uses zkp batches of 10 (batch size 1000), a real
// configuration with its own verifying key. The 1,996 unrelated nullifiers
// around the spend run through the same queue and apply code the program runs,
// host-side on the account bytes, with real roots from a reference tree; only
// their batch proofs are skipped. The spend, the boundary-crossing batch
// insert, the close and the replays are real transactions with real proofs.

type NullifierTree = IndexedMerkleTree<Poseidon, usize>;
type NullifierTreeAccount = NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES>;

const BOUNDARY_ZKP_BATCH_SIZE: u64 = 10;
const BOUNDARY_BATCH_SIZE: u64 = BOUNDARY_ZKP_BATCH_SIZE * NULLIFIER_TREE_ZKP_BATCHES as u64;

fn boundary_env() -> Pool {
    let mut env = proof_env();
    let authority = env.authority.insecure_clone();
    let tree = env
        .rpc
        .create_tree_with_nullifier_params(
            &authority,
            NullifierTreeInitParams {
                input_queue_batch_size: BOUNDARY_BATCH_SIZE,
                input_queue_zkp_batch_size: BOUNDARY_ZKP_BATCH_SIZE,
                height: NULLIFIER_TREE_HEIGHT,
            },
        )
        .expect("create a tree with zkp batches of 10");
    env.tree_id = env
        .rpc
        .account_data(&tree)
        .as_deref()
        .and_then(read_tree_id)
        .expect("tree id");
    env.tree = tree;
    env
}

fn nullifier_root_at(env: &Pool, index: u16) -> Option<[u8; 32]> {
    let mut data = env.rpc.account_data(&env.tree)?;
    let account = TreeAccount::from_bytes(&mut data, env.tree.to_bytes()).ok()?;
    account.get_nullifier_tree_root(index).ok()
}

fn utxo_root_at(env: &Pool, index: u16) -> Option<[u8; 32]> {
    let mut data = env.rpc.account_data(&env.tree)?;
    let account = TreeAccount::from_bytes(&mut data, env.tree.to_bytes()).ok()?;
    account.get_utxo_tree_root(index).ok()
}

/// Run `read` on a copy of the tree account's nullifier tree.
fn read_nullifier_tree<T>(env: &Pool, read: impl FnOnce(&mut NullifierTreeAccount) -> T) -> T {
    let mut data = env.rpc.account_data(&env.tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, env.tree.to_bytes()).expect("load tree");
    read(account.nullifier_tree())
}

fn nullifier_root_history(env: &Pool) -> Vec<[u8; 32]> {
    read_nullifier_tree(env, |tree| tree.root_history.roots.to_vec())
}

/// Run `update` on the tree account's nullifier tree and write it back.
fn update_nullifier_tree<T>(
    env: &mut Pool,
    update: impl FnOnce(&mut NullifierTreeAccount) -> T,
) -> T {
    let mut account = env.rpc.svm.get_account(&env.tree).expect("tree account");
    let result = {
        let mut tree =
            TreeAccount::from_bytes(&mut account.data, env.tree.to_bytes()).expect("load tree");
        update(tree.nullifier_tree())
    };
    env.rpc
        .svm
        .set_account(env.tree, account)
        .expect("write tree account");
    result
}

/// Other users' spends: queue `values` through the program's queue code.
fn seed_queue(env: &mut Pool, values: &[[u8; 32]]) {
    update_nullifier_tree(env, |tree| {
        for value in values {
            tree.insert_nullifier_into_queue(value)
                .expect("queue a seeded nullifier");
        }
    });
}

/// A forester update the program would accept: the next zkp batch's values
/// appended to the reference tree, applied through the program's apply code.
/// Only the batch proof is skipped.
fn seed_zkp_batch_update(env: &mut Pool, reference: &mut NullifierTree, values: &[[u8; 32]]) {
    let old_root = reference.root();
    for value in values {
        reference
            .append(&BigUint::from_bytes_be(value))
            .expect("append to the reference tree");
    }
    let new_root = reference.root();
    let hash_chain = create_hash_chain_4_from_slice(values).expect("zkp batch hash chain");
    let tree_pubkey = env.tree.to_bytes();
    update_nullifier_tree(env, |tree| {
        assert_eq!(
            tree.get_root(),
            Some(old_root),
            "reference tracks the on-chain root"
        );
        let pending = tree.pending_batch_index as usize;
        let batch = tree.batches.get_mut(pending).expect("pending batch");
        let zkp_batch_index = batch.get_first_ready_zkp_batch().expect("ready zkp batch") as usize;
        assert_eq!(
            batch.hash_chain(zkp_batch_index),
            Some(hash_chain),
            "the queue holds exactly these values in this zkp batch"
        );
        batch.set_cached_tree_update(
            zkp_batch_index,
            CachedTreeUpdate {
                old_root,
                new_root,
                occupied: 1,
            },
        );
        let event = tree
            .apply_cached_tree_updates(tree_pubkey)
            .expect("apply the update")
            .expect("one zkp batch applied");
        assert_eq!((event.num_update, event.new_root), (1, new_root));
    });
}

/// The forester's real `batch_update_nullifier_tree` for the next zkp batch:
/// a batch address-append proof from the prover, verified on chain.
fn send_batch_update(env: &mut Pool, reference: &mut NullifierTree, values: &[[u8; 32]]) {
    let (old_root, zkp_batch_index, leaves_hash_chain, start_index) =
        read_nullifier_tree(env, |tree| {
            let pending = tree.pending_batch_index as usize;
            let zkp_batch_index = tree
                .batches
                .get(pending)
                .expect("pending batch")
                .get_first_ready_zkp_batch()
                .expect("ready zkp batch") as usize;
            (
                tree.get_root().expect("current root"),
                zkp_batch_index,
                tree.get_hash_chain(pending, zkp_batch_index)
                    .expect("zkp batch hash chain"),
                tree.next_index,
            )
        });
    assert_eq!(
        reference.root(),
        old_root,
        "reference tracks the on-chain root"
    );

    let mut low_element_values = Vec::with_capacity(values.len());
    let mut low_element_indices = Vec::with_capacity(values.len());
    let mut low_element_next_values = Vec::with_capacity(values.len());
    let mut new_element_values = Vec::with_capacity(values.len());
    let mut low_element_proofs = Vec::with_capacity(values.len());
    let mut new_element_proofs = Vec::with_capacity(values.len());
    for (offset, value) in values.iter().enumerate() {
        let value = BigUint::from_bytes_be(value);
        let non_inclusion = reference
            .get_non_inclusion_proof(&value)
            .expect("low element proof");
        low_element_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_lower_range_value,
        ));
        low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
        low_element_next_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_higher_range_value,
        ));
        low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
        new_element_values.push(value.clone());
        reference
            .append(&value)
            .expect("append to the reference tree");
        let new_proof = reference
            .get_proof_of_leaf(start_index as usize + offset, true)
            .expect("new element proof");
        new_element_proofs.push(path_to_biguint(new_proof.to_vec()));
    }
    let new_root = reference.root();
    let mut start_index_bytes = [0u8; 32];
    start_index_bytes[24..].copy_from_slice(&start_index.to_be_bytes());
    let public_input_hash =
        create_hash_chain_4_from_slice(&[old_root, new_root, leaves_hash_chain, start_index_bytes])
            .expect("public input hash");
    let inputs = BatchAddressAppendInputs {
        public_input_hash: BigUint::from_bytes_be(&public_input_hash),
        old_root: BigUint::from_bytes_be(&old_root),
        new_root: BigUint::from_bytes_be(&new_root),
        hashchain_hash: BigUint::from_bytes_be(&leaves_hash_chain),
        start_index,
        low_element_values,
        low_element_indices,
        low_element_next_values,
        new_element_values,
        low_element_proofs,
        new_element_proofs,
        tree_height: NULLIFIER_TREE_HEIGHT,
        batch_size: values.len() as u32,
    };
    let proof = ProverClient::local()
        .prove_batch_address_append(&inputs)
        .expect("batch address-append proof");
    let proof = ProofCompressed::try_from(proof).expect("compress batch proof");
    let authority = env.authority.insecure_clone();
    let ix = BatchUpdateNullifierTree {
        authority: authority.pubkey(),
        tree: env.tree,
        reimbursement_recipient: authority.pubkey(),
        new_root,
        old_root,
        zkp_batch_index: u16::try_from(zkp_batch_index).expect("zkp batch index"),
        proof_a: proof.a,
        proof_b: proof.b,
        proof_c: proof.c,
    }
    .instruction();
    env.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[&authority],
            ComputeBudgetConfig::new(1_400_000),
        )
        .expect("verified batch update");
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.iter()
        .map(|node| BigUint::from_bytes_be(node))
        .collect()
}

fn send_close(env: &mut Pool, nullifiers: &[[u8; 32]]) -> Result<(), ProgramTestError> {
    let authority = env.authority.insecure_clone();
    let ix = CloseNullifierPdas {
        authority: authority.pubkey(),
        tree: env.tree,
        reimbursement_recipient: env.rpc.payer.pubkey(),
        nullifiers: nullifiers.to_vec(),
    }
    .instruction();
    env.rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .map(|_| ())
}

#[track_caller]
fn assert_close_rejected(env: &mut Pool, nullifiers: &[[u8; 32]]) {
    let error = send_close(env, nullifiers).expect_err("the nullifier PDAs must not close yet");
    Rejection::pool(ShieldedPoolError::NullifierPdaNotClosable).assert_litesvm(error);
    assert_nullifier_pdas(&env.rpc, &env.tree, nullifiers).expect("nullifier PDAs kept");
}

#[track_caller]
fn assert_replay_rejected(env: &mut Pool, data: TransactIxData, expected: ShieldedPoolError) {
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(env, data)], &[])
        .expect_err("a second spend of the nullifier must be rejected");
    Rejection::pool(expected).assert_litesvm(error);
}

/// The replay as it would run had its nullifier PDAs been closed: sent with
/// the PDAs deleted, after which the whole SVM state is restored.
fn replay_without_nullifier_pdas(
    env: &mut Pool,
    data: TransactIxData,
) -> Result<(), ProgramTestError> {
    let snapshot = env.rpc.svm.clone();
    for nullifier_pda in nullifier_pda_addresses(&env.tree, &nullifiers_of(&data)) {
        env.rpc
            .svm
            .set_account(nullifier_pda, Account::default())
            .expect("delete the nullifier PDA");
    }
    let ix = transact_instruction(env, data);
    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .map(|_| ());
    env.rpc.svm = snapshot;
    result
}

#[test]
fn nullifier_pda_closes_only_after_its_pre_insertion_roots_are_overwritten() {
    let mut env = boundary_env();
    let zkp = BOUNDARY_ZKP_BATCH_SIZE as usize;
    let zkp_batches = NULLIFIER_TREE_ZKP_BATCHES;
    let mut reference = nullifier_tree().expect("reference nullifier tree");
    let seeded =
        |first: u64, count: usize| -> Vec<[u8; 32]> { (first..).take(count).map(fe).collect() };

    // Batch 0: other users fill zkp batches 0..=98 and the first 8 slots of
    // zkp batch 99, and the forester applies zkp batches 0..=98.
    let batch_0 = seeded(1_000_000, zkp * zkp_batches - 2);
    seed_queue(&mut env, &batch_0);
    for values in batch_0.chunks(zkp).take(zkp_batches - 1) {
        seed_zkp_batch_update(&mut env, &mut reference, values);
    }
    let pre_insertion_root_index = (zkp_batches - 1) as u16;
    let pre_insertion_root = reference.root();
    assert_eq!(
        nullifier_root_at(&env, pre_insertion_root_index),
        Some(pre_insertion_root),
        "update 99 wrote the latest root into slot 99"
    );

    // The spend: a real proof against the latest root, queueing both
    // nullifiers as the last two values of batch 0.
    let spend = build_transact_ix(&mut env, &reference, pre_insertion_root_index);
    let nullifiers = nullifiers_of(&spend);

    // The harness stays in one slot, and a UTXO append overwrites the root of
    // an earlier append in its slot. The spend runs one slot after the deposit
    // so the UTXO root its proof names stays accepted: a replay can then be
    // rejected only for its nullifiers.
    let utxo_root_index = spend
        .tree_contexts
        .first()
        .expect("input tree context")
        .utxo_tree_root_index;
    let utxo_root = utxo_root_at(&env, utxo_root_index).expect("utxo root");
    let slot = env.rpc.svm.get_sysvar::<Clock>().slot;
    env.rpc.warp_to_slot(slot + 1).expect("next slot");
    env.rpc
        .create_and_send_default_payer_transaction(
            &[transact_instruction(&env, spend.clone())],
            &[],
        )
        .expect("the first spend");
    assert_eq!(
        utxo_root_at(&env, utxo_root_index),
        Some(utxo_root),
        "the spend's outputs leave the UTXO root of its proof accepted"
    );
    let first_queue_index = BOUNDARY_BATCH_SIZE - 1;
    for (nullifier, offset) in nullifiers.iter().zip(0..) {
        assert_nullifier_pda(&env.rpc, &env.tree, nullifier, first_queue_index + offset)
            .expect("nullifier PDA at the end of batch 0");
    }

    // Update 100 inserts the spent nullifiers. Batch 0 is fully inserted,
    // which moves the watermark only to batch 0's start, so it releases the
    // PDAs of earlier batches and none of batch 0's.
    let last_zkp_batch_0: Vec<[u8; 32]> = batch_0
        .chunks(zkp)
        .nth(zkp_batches - 1)
        .expect("zkp batch 99 seeds")
        .iter()
        .chain(&nullifiers)
        .copied()
        .collect();
    seed_zkp_batch_update(&mut env, &mut reference, &last_zkp_batch_0);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree).expect("watermark"),
        1
    );
    assert_close_rejected(&mut env, &nullifiers);

    // Batch 1: other users fill it and the forester applies updates 101..=198.
    // Every root from update 101 on contains the spent nullifiers.
    let batch_1 = seeded(2_000_000, zkp * zkp_batches);
    seed_queue(&mut env, &batch_1);
    let mut batch_1_updates = batch_1.chunks(zkp);
    let mut post_insertion_roots = Vec::with_capacity(zkp_batches);
    for values in batch_1_updates.by_ref().take(zkp_batches - 2) {
        seed_zkp_batch_update(&mut env, &mut reference, values);
        post_insertion_roots.push(reference.root());
    }

    // The pre-insertion root is still accepted: a replay proven against it
    // is stopped only by the nullifier PDAs, which therefore must not close.
    // Without them the same transaction is a second spend.
    assert_eq!(
        nullifier_root_at(&env, pre_insertion_root_index),
        Some(pre_insertion_root),
        "the pre-insertion root survives until update 199"
    );
    assert_replay_rejected(
        &mut env,
        spend.clone(),
        ShieldedPoolError::NullifierAlreadyQueued,
    );
    replay_without_nullifier_pdas(&mut env, spend.clone())
        .expect("with its nullifier PDAs closed at update 198 the replay is a double spend");
    assert_close_rejected(&mut env, &nullifiers);

    // Update 199 overwrites the pre-insertion root, and from here the root
    // history alone rejects the replay. The PDAs stay: the watermark waits
    // for the whole batch.
    let update_199 = batch_1_updates.next().expect("zkp batch 98 of batch 1");
    seed_zkp_batch_update(&mut env, &mut reference, update_199);
    post_insertion_roots.push(reference.root());
    assert!(
        !nullifier_root_history(&env).contains(&pre_insertion_root),
        "update 199 overwrote the last pre-insertion root"
    );
    let error = replay_without_nullifier_pdas(&mut env, spend.clone())
        .expect_err("no accepted root lets the replay through after update 199");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree).expect("watermark"),
        1
    );
    assert_close_rejected(&mut env, &nullifiers);

    // Update 200, a real verified batch update, fully inserts batch 1 and
    // moves the watermark to its start, past the spent nullifiers.
    let update_200 = batch_1_updates.next().expect("zkp batch 99 of batch 1");
    send_batch_update(&mut env, &mut reference, update_200);
    post_insertion_roots.push(reference.root());
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree).expect("watermark"),
        BOUNDARY_BATCH_SIZE + 1,
        "the watermark moves to batch 1's start"
    );
    send_close(&mut env, &nullifiers).expect("close the spent nullifiers' PDAs");
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers).expect("nullifier PDAs closed");

    // The replay from the report: the accepted roots are exactly the roots of
    // updates 101..=200, update `n` in slot `n % 100`. Each contains the spent
    // nullifiers, so no non-inclusion proof exists against any of them, and
    // the original proof verifies at no root index.
    let history = nullifier_root_history(&env);
    let mut expected_history = vec![[0u8; 32]; zkp_batches];
    for (root, update) in post_insertion_roots.iter().zip(zkp_batches + 1..) {
        *expected_history
            .get_mut(update % zkp_batches)
            .expect("root history slot") = *root;
    }
    assert_eq!(
        history, expected_history,
        "every accepted root was written after the spent nullifiers were inserted"
    );
    for nullifier in &nullifiers {
        assert!(
            reference
                .get_non_inclusion_proof(&BigUint::from_bytes_be(nullifier))
                .is_err(),
            "the spent nullifier is in the tree"
        );
    }
    for root_index in 0..history.len() as u16 {
        let mut replay = spend.clone();
        replay.tree_contexts = tree_contexts(&[(
            replay
                .tree_contexts
                .first()
                .expect("input tree context")
                .utxo_tree_root_index,
            root_index,
        )]);
        assert_replay_rejected(
            &mut env,
            replay,
            ShieldedPoolError::TransactProofVerificationFailed,
        );
    }
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("rejected replays create no nullifier PDA");
}
