//! Runs `test-vectors/transact_functional.json` against the default ring.
//!
//! Every step settles as a top-level Shielded Pool `transact` on the
//! `ConfidentialEddsa` rail: the vector's hidden owner authorizes inside the
//! proof, public co-owners sign the transaction, and a separate fee payer pays.
//! The runner goes through the same client path a wallet uses
//! (`ConfidentialTransaction`, `Submission`, the in-process indexer), so a
//! case that settles here settles for a real client.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, ensure, Context, Result};
use solana_address::Address;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    sign_transaction, ProofDataSource, ProverClient, Rpc, SignedPrivateTransaction, SprClient,
    Submission,
};
use spr_interface::{
    instruction::instruction_data::CreateCacheData,
    pda,
    shape::{Shape, CONFIDENTIAL_EDDSA_SHAPES},
    state::{cache::CacheAccount, SplAssetRegistry},
};
use spr_keypair::ShieldedKeypair;
use spr_program::instruction::{
    CreateCache, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
};
use spr_program_test::{ProgramTestHandle, SprProgramTest};
use spr_test_utils::{
    functional_vectors::{
        Asset, Direction, FunctionalVector, InputSlot, NoteBalance, Padding, Role, Step,
    },
    nullifier_pda::assert_nullifier_pdas,
    utxo::ProofKeys,
    wallet::{KeypairWalletAuthority, Wallet, DEFAULT_TAG_WINDOW},
};
use spr_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    utxo::SppProofInputUtxo,
    AssetRegistry, Mint, ShieldedTransaction, SppProofOutputUtxo, Utxo, WalletUtxo,
};

use super::{
    fixtures::Pool,
    transact::{proof_env, tree_progress},
};

/// Lamports every actor starts with: fees, rent and any public deposit.
const ACTOR_LAMPORTS: u64 = 10_000_000_000;
/// The SOL interface's balance before the first deposit, above its rent minimum.
const SOL_INTERFACE_LAMPORTS: u64 = 1_000_000_000;
/// Tokens minted to every token account that pays deposits.
const TOKEN_SUPPLY: u64 = 1_000_000_000;
/// How long a seated cache stays readable.
const CACHE_LIFETIME_SECONDS: i64 = 3_600;

/// Runs one vector on a fresh pool and checks every expectation it states.
pub struct VectorRun<'a> {
    pub vector: &'a FunctionalVector,
}

impl VectorRun<'_> {
    pub fn execute(self) -> Result<()> {
        let vector = self.vector;
        ensure!(
            vector.rings.default.is_run(),
            "{} does not run on the default ring: {:?}",
            vector.name,
            vector.rings.default
        );
        let mut runner = Runner::new(vector)?;
        for (index, step) in vector.steps.iter().enumerate() {
            runner
                .step(step)
                .with_context(|| format!("{} step {index}", vector.name))?;
        }
        runner
            .assert_unspent(vector)
            .with_context(|| format!("{} unspent notes", vector.name))
    }
}

struct Actor {
    solana: Keypair,
    shielded: ShieldedKeypair,
}

struct Tree {
    address: Pubkey,
    id: u16,
}

/// A data-bearing output the runner sent, to rebuild as a spendable note.
struct DataNote<'a> {
    owner: Role,
    encrypted: &'a SppProofOutputUtxo,
    data_hash: [u8; 32],
    tree_id: u16,
    signature: Signature,
}

/// A token mint the vector names, with the token accounts its roles use.
struct Token {
    mint: Mint,
    token_program: Pubkey,
    /// The token account of each role a public leg names, and of the harness
    /// payer, which funds proofless deposits.
    accounts: BTreeMap<Option<Role>, Pubkey>,
}

struct Runner {
    client: SprClient<ProgramTestHandle, ProgramTestHandle>,
    actors: BTreeMap<Role, Actor>,
    trees: Vec<Tree>,
    tokens: BTreeMap<Asset, Token>,
    /// Every note the scenario created and has not spent, by vector note id.
    notes: BTreeMap<String, WalletUtxo>,
    /// Proofless deposits as shielded transactions, for wallet discovery.
    deposits: Vec<ShieldedTransaction>,
    /// The cache the vector's cached inputs read, with each note's slot.
    cache: Option<SeatedCache>,
}

struct SeatedCache {
    address: Pubkey,
    slots: BTreeMap<String, u8>,
}

impl Runner {
    fn new(vector: &FunctionalVector) -> Result<Self> {
        let mut pool = proof_env();
        let mut trees = vec![Tree {
            address: pool.tree,
            id: pool.tree_id,
        }];
        if uses_second_tree(vector) {
            let address = pool.rpc.create_tree(&pool.authority)?;
            let id = pool
                .rpc
                .account_data(&address)
                .as_deref()
                .and_then(spr_interface::state::read_tree_id)
                .ok_or_else(|| anyhow!("read the id of tree {address}"))?;
            trees.push(Tree { address, id });
        }

        // A live pool's SOL interface already holds its rent; the vectors move
        // amounts far below that, so the first deposit must not have to cover it.
        pool.rpc
            .airdrop(&pda::sol_interface(), SOL_INTERFACE_LAMPORTS)?;

        let mut actors = BTreeMap::new();
        for (role, seed) in &vector.actors {
            let solana = Keypair::new_from_array(seed.0);
            pool.rpc.airdrop(&solana.pubkey(), ACTOR_LAMPORTS)?;
            let shielded = ShieldedKeypair::from_keypair(&solana)?;
            actors.insert(*role, Actor { solana, shielded });
        }
        let tokens = TokenSetup {
            pool: &mut pool,
            actors: &actors,
            vector,
        }
        .create()?;

        let mut notes = BTreeMap::new();
        let mut deposits = Vec::new();
        let funder = pool.rpc.payer.insecure_clone();
        for funded in &vector.funding {
            let owner = actor(&actors, funded.owner)?;
            let tree = trees
                .get(usize::from(funded.tree))
                .ok_or_else(|| anyhow!("tree {}", funded.tree))?;
            let recipient = owner.shielded.shielded_address()?;
            let data = match funded.asset {
                Asset::Sol => SprProgramTest::wallet_sol_shield_data(funded.amount, &recipient)?,
                asset => {
                    let token = token(&tokens, asset)?;
                    let mut data = SprProgramTest::wallet_spl_shield_data(
                        funded.amount,
                        &recipient,
                        &token.mint.asset,
                        &token.account(None)?,
                    )?;
                    data.asset = SprProgramTest::spl_asset_with_program(
                        &token.mint.asset,
                        &token.account(None)?,
                        token.token_program,
                    );
                    data
                }
            };
            let deposit = pool.rpc.deposit(&tree.address, &funder, &data)?;
            let utxo = pool
                .rpc
                .indexed_deposit_utxo(&deposit, owner.shielded.signing_pubkey())?;
            let nullifier_pubkey = owner.shielded.nullifier_key.pubkey()?;
            let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree.id)?;
            ensure!(utxo_hash == deposit.utxo_hash, "deposit {} hash", funded.id);
            let nullifier = utxo.nullifier(&utxo_hash, &owner.shielded.nullifier_key)?;
            deposits.push(deposit.to_shielded_transaction(Signature::default(), tree.id));
            notes.insert(
                funded.id.clone(),
                WalletUtxo {
                    utxo,
                    nullifier_pubkey,
                    utxo_hash,
                    nullifier,
                    tx_viewing_key: None,
                    data_hash: None,
                    ring_data_hash: None,
                    tree_id: tree.id,
                    leaf_index: deposit.leaf_index,
                    latest_tree_id: None,
                    slot: 0,
                    tx_signature: Signature::default(),
                    slot_index: 0,
                },
            );
        }

        let cache = seat_cache(&mut pool.rpc, vector, &notes)?;
        let client = pool
            .rpc
            .into_client(ProverClient::local())
            .with_proof_data_source(ProofDataSource::Client);
        Ok(Self {
            client,
            actors,
            trees,
            tokens,
            notes,
            deposits,
            cache,
        })
    }

    fn actor(&self, role: Role) -> Result<&Actor> {
        actor(&self.actors, role)
    }

    fn tree(&self, index: u8) -> Result<&Tree> {
        self.trees
            .get(usize::from(index))
            .ok_or_else(|| anyhow!("tree {index}"))
    }

    fn mint(&self, asset: Asset) -> Result<Mint> {
        match asset {
            Asset::Sol => Ok(Mint::SOL),
            asset => Ok(token(&self.tokens, asset)?.mint),
        }
    }

    fn asset_of(&self, mint: &Mint) -> Result<Asset> {
        if *mint == Mint::SOL {
            return Ok(Asset::Sol);
        }
        self.tokens
            .iter()
            .find(|(_, token)| token.mint.asset == mint.asset)
            .map(|(asset, _)| *asset)
            .ok_or_else(|| anyhow!("unknown mint {:?}", mint.asset))
    }

    fn step(&mut self, step: &Step) -> Result<()> {
        let hidden = self.actor(step.hidden_owner)?;
        let payer = self.actor(step.fee_payer)?;
        let payer_address = payer.solana.pubkey();

        // 1. The real inputs, in slot order: the client places addresses first.
        let mut inputs = Vec::with_capacity(step.inputs.len());
        let mut addresses = Vec::new();
        let mut nullifier_keys = Vec::new();
        for (position, slot) in step.inputs.iter().enumerate() {
            match slot {
                InputSlot::Utxo { note, owner, .. } => {
                    inputs.push(
                        self.notes
                            .get(note)
                            .cloned()
                            .ok_or_else(|| anyhow!("note {note} is not held"))?,
                    );
                    nullifier_keys.push(&self.actor(*owner)?.shielded.nullifier_key);
                }
                InputSlot::Address {
                    owner, seed, tree, ..
                } => {
                    ensure!(
                        inputs.is_empty(),
                        "address slot {position} follows a note, which the client cannot build"
                    );
                    addresses.push(SppProofInputUtxo::new_address(
                        self.actor(*owner)?.shielded.signing_pubkey(),
                        seed.0,
                        self.tree(*tree)?.id,
                    )?);
                }
            }
        }
        let published_nullifiers: Vec<(u16, [u8; 32])> = addresses
            .iter()
            .map(|address| (address.tree_id, address.nullifier))
            .chain(inputs.iter().map(|input| (input.tree_id, input.nullifier)))
            .collect();

        // 2. The transaction: signers select the in-circuit owner rail.
        let mut expected_signers = Vec::with_capacity(step.expect.transaction_signers.len());
        for role in &step.expect.transaction_signers {
            expected_signers.push(self.actor(*role)?.solana.pubkey());
        }
        let mut transaction = match step.padding {
            Padding::Dummy => {
                ConfidentialTransaction::new_with_addresses(inputs, addresses, payer_address)?
            }
            Padding::Compact => ConfidentialTransaction::new_compact_with_addresses(
                inputs,
                addresses,
                payer_address,
            )?,
        }
        .with_transaction_signers(&expected_signers)
        .with_output_tree_id(self.tree(step.output_tree)?.id)?;
        for output in &step.outputs {
            let mut utxo = SppProofOutputUtxo {
                owner_address: Some(self.actor(output.owner)?.shielded.shielded_address()?),
                asset: self.mint(output.asset)?,
                amount: output.amount,
                ..Default::default()
            };
            // SPP commits the hash, not the data; the hash bytes stand in for
            // an application payload.
            if let Some(data_hash) = output.data_hash {
                utxo = utxo.with_utxo_data(data_hash.0.to_vec(), data_hash.0);
            }
            transaction.add_output_utxo(utxo)?;
        }
        let settlement_transfers = self.add_public_legs(step, &mut transaction)?;
        let shape = shape_for(step)?;
        transaction.pad_utxos(shape, &hidden.shielded.shielded_address()?)?;
        let proof_inputs = self.read_cache(step, transaction.encrypt(&hidden.shielded)?)?;
        let encrypted_outputs: Vec<SppProofOutputUtxo> = proof_inputs
            .output_utxos
            .iter()
            .take(step.outputs.len())
            .cloned()
            .collect();
        let signed = SignedPrivateTransaction {
            transaction: proof_inputs,
            settlement_transfers,
        };

        // 3. Prove and sign: the hidden owner authorizes inside the proof.
        let authority = ProofKeys(&nullifier_keys);
        let unsigned = Submission::new(&signed, payer_address, &authority)
            .with_confidential_eddsa_owner(&hidden.shielded.signing_key)
            .finish_unsigned_sync(&self.client)?;
        let required = usize::from(unsigned.message.header().num_required_signatures);
        let mut signed_by: Vec<Pubkey> = unsigned
            .message
            .static_account_keys()
            .get(..required)
            .ok_or_else(|| anyhow!("message lists fewer keys than signatures"))?
            .to_vec();
        signed_by.sort();
        let mut expected_sorted = expected_signers.clone();
        expected_sorted.sort();
        ensure!(
            signed_by == expected_sorted,
            "transaction signers {signed_by:?}, expected {expected_sorted:?}"
        );
        for role in &step.expect.absent_signers {
            let key = self.actor(*role)?.solana.pubkey();
            ensure!(!signed_by.contains(&key), "{role} signs the transaction");
        }
        let program_ids: Vec<Pubkey> = unsigned
            .message
            .instructions()
            .iter()
            .filter_map(|instruction| {
                unsigned
                    .message
                    .static_account_keys()
                    .get(usize::from(instruction.program_id_index))
                    .copied()
            })
            .collect();
        ensure!(
            program_ids == [spr_interface::PROGRAM_ID_PUBKEY],
            "top-level instructions {program_ids:?}, expected one Shielded Pool transact"
        );
        if let Some(cache) = signed.transaction.cache_accounts.read {
            ensure!(
                unsigned.message.static_account_keys().contains(&cache),
                "the transact does not pass the cache it reads"
            );
        }
        let mut signers: Vec<&dyn Signer> = Vec::new();
        for role in &step.expect.transaction_signers {
            signers.push(&self.actor(*role)?.solana);
        }
        let transaction = sign_transaction(unsigned.message, &signers)?;

        // 4. Settle, then check the trees, the public balances and the nullifiers.
        let before = self.progress();
        let balances_before = self.public_balances(step)?;
        let signature = self.client.process_transaction(transaction)?;
        self.client.confirm_private_transaction_sync(signature)?;
        let after = self.progress();
        let balances_after = self.public_balances(step)?;
        for ((role, asset), before) in &balances_before {
            let after = balances_after
                .get(&(*role, *asset))
                .copied()
                .unwrap_or_default();
            let moved = i128::from(after) - i128::from(*before);
            let expected = step
                .expect
                .public_deltas
                .get(role)
                .and_then(|deltas| deltas.get(asset))
                .map(|delta| delta.0)
                .unwrap_or_default();
            ensure!(
                moved == expected,
                "{role}'s {} balance moved {moved}, expected {expected}",
                asset.label()
            );
        }
        let (published_inputs, published_outputs) = match step.padding {
            Padding::Dummy => (shape.n_inputs(), shape.n_outputs()),
            Padding::Compact => (step.inputs.len(), step.outputs.len()),
        };
        ensure!(
            after.0 - before.0 == u64::try_from(published_outputs)?,
            "{} leaves appended, expected {published_outputs}",
            after.0 - before.0
        );
        ensure!(
            after.1 - before.1 == u64::try_from(published_inputs)?,
            "{} nullifiers queued, expected {published_inputs}",
            after.1 - before.1
        );
        ensure!(
            usize::try_from(step.expect.real_inputs)? == published_nullifiers.len()
                && usize::try_from(step.expect.real_outputs)? == step.outputs.len(),
            "the vector's real slot counts disagree with its slots"
        );
        for tree in &self.trees {
            let nullifiers: Vec<[u8; 32]> = published_nullifiers
                .iter()
                .filter(|(tree_id, _)| *tree_id == tree.id)
                .map(|(_, nullifier)| *nullifier)
                .collect();
            if !nullifiers.is_empty() {
                let rpc = self.client.indexer().lock();
                assert_nullifier_pdas(&*rpc, &tree.address, &nullifiers)
                    .map_err(|error| anyhow!("nullifier PDAs in {}: {error}", tree.address))?;
            }
        }

        // 5. Track the step's notes by the vector's ids.
        for slot in &step.inputs {
            if let InputSlot::Utxo { note, .. } = slot {
                self.notes.remove(note);
            }
        }
        let output_tree_id = self.tree(step.output_tree)?.id;
        for (output, encrypted) in step.outputs.iter().zip(encrypted_outputs) {
            let held = match output.data_hash {
                // The owner's wallet finds a plain note by itself.
                None => self
                    .synced_wallet(output.owner)?
                    .unspent()
                    .find(|held| held.utxo.blinding == encrypted.blinding)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!("{} does not find output {}", output.owner, output.id)
                    })?,
                // A data note's hash is the application's to recompute, so
                // the runner rebuilds the note it sent and finds its leaf.
                Some(data_hash) => self.data_note(DataNote {
                    owner: output.owner,
                    encrypted: &encrypted,
                    data_hash: data_hash.0,
                    tree_id: output_tree_id,
                    signature,
                })?,
            };
            self.notes.insert(output.id.clone(), held);
        }
        Ok(())
    }

    /// Points every cached input of `step` at its cache slot. The input slots
    /// of the proof follow the step's order, addresses first, which is the
    /// order the vector lists them in.
    fn read_cache(&self, step: &Step, mut proof_inputs: SppProofInputs) -> Result<SppProofInputs> {
        let mut reads = false;
        for (slot, input) in step.inputs.iter().zip(proof_inputs.input_utxos.iter_mut()) {
            if let InputSlot::Utxo {
                note, cached: true, ..
            } = slot
            {
                let cache = self
                    .cache
                    .as_ref()
                    .ok_or_else(|| anyhow!("no cache is seated"))?;
                let cache_slot = cache
                    .slots
                    .get(note)
                    .copied()
                    .ok_or_else(|| anyhow!("note {note} is not seated in the cache"))?;
                *input = input.clone().with_cache_slot(cache_slot)?;
                reads = true;
            }
        }
        if reads {
            let cache = self
                .cache
                .as_ref()
                .ok_or_else(|| anyhow!("no cache is seated"))?;
            proof_inputs = proof_inputs.with_read_cache(cache.address);
        }
        Ok(proof_inputs)
    }

    /// The note `data` describes, confirmed against its indexed output slot.
    fn data_note(&self, data: DataNote<'_>) -> Result<WalletUtxo> {
        let owner = &self.actor(data.owner)?.shielded;
        let utxo = Utxo {
            owner: owner.signing_pubkey(),
            asset: data.encrypted.asset,
            amount: data.encrypted.amount,
            blinding: data.encrypted.blinding,
            ring_program_id: None,
            data: Default::default(),
        };
        let nullifier_pubkey = owner.nullifier_key.pubkey()?;
        let utxo_hash = utxo.hash(&nullifier_pubkey, &data.data_hash, &[0; 32], data.tree_id)?;
        ensure!(
            utxo_hash == data.encrypted.hash(data.tree_id)?,
            "the rebuilt data note does not match the output the proof committed"
        );
        let leaf_index = self
            .client
            .indexer()
            .lock()
            .indexer()
            .transactions()
            .iter()
            .filter(|transaction| transaction.tx_signature == data.signature)
            .flat_map(|transaction| &transaction.output_slots)
            .find(|slot| slot.output_context.hash == utxo_hash)
            .map(|slot| slot.output_context.leaf_index)
            .ok_or_else(|| anyhow!("no indexed output slot holds the data note"))?;
        let nullifier = utxo.nullifier(&utxo_hash, &owner.nullifier_key)?;
        Ok(WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            tx_viewing_key: None,
            data_hash: Some(data.data_hash),
            ring_data_hash: None,
            tree_id: data.tree_id,
            leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: data.signature,
            slot_index: 0,
        })
    }

    /// Adds the step's public legs and returns their settlement account
    /// groups, which follow the order the legs are added in.
    fn add_public_legs(
        &self,
        step: &Step,
        transaction: &mut ConfidentialTransaction,
    ) -> Result<Vec<TransactInterfaceTransferAccounts>> {
        let mut groups = Vec::with_capacity(step.public.len());
        for leg in &step.public {
            let account = self.actor(leg.account)?.solana.pubkey();
            let group = match (leg.direction, leg.asset) {
                (Direction::Deposit, Asset::Sol) => {
                    transaction.deposit_sol(leg.amount, account)?;
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: account,
                    })
                }
                (Direction::Withdrawal, Asset::Sol) => {
                    transaction.withdraw_to(Mint::SOL.asset, leg.amount, account, None)?
                }
                (Direction::Deposit, asset) => {
                    let token = token(&self.tokens, asset)?;
                    let user_token_account = token.account(Some(leg.account))?;
                    transaction.deposit(token.mint, leg.amount, user_token_account)?;
                    TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                        mint: token.mint.asset,
                        spl_interface: pda::spl_interface(&token.mint.asset),
                        token_authority: account,
                        user_token_account,
                        token_program: token.token_program,
                    })
                }
                (Direction::Withdrawal, asset) => {
                    let token = token(&self.tokens, asset)?;
                    let user_token_account = token.account(Some(leg.account))?;
                    transaction.withdraw(token.mint.asset, leg.amount, user_token_account)?;
                    TransactInterfaceTransferAccounts::SplWithdrawal(
                        TransactSplWithdrawalAccounts {
                            mint: token.mint.asset,
                            spl_interface: pda::spl_interface(&token.mint.asset),
                            user_token_account,
                            token_program: token.token_program,
                        },
                    )
                }
            };
            groups.push(group);
        }
        Ok(groups)
    }

    /// The public balance of every account a leg of `step` names, per asset.
    fn public_balances(&self, step: &Step) -> Result<BTreeMap<(Role, Asset), u64>> {
        let rpc = self.client.indexer().lock();
        let mut balances = BTreeMap::new();
        for leg in &step.public {
            let balance = match leg.asset {
                Asset::Sol => rpc
                    .svm
                    .get_account(&self.actor(leg.account)?.solana.pubkey())
                    .map(|account| account.lamports)
                    .unwrap_or_default(),
                asset => {
                    let account = token(&self.tokens, asset)?.account(Some(leg.account))?;
                    rpc.token_balance(&account)
                        .ok_or_else(|| anyhow!("token account {account}"))?
                }
            };
            balances.insert((leg.account, leg.asset), balance);
        }
        Ok(balances)
    }

    /// Leaves appended and nullifiers queued, summed over every tree.
    fn progress(&self) -> (u64, u64) {
        let rpc = self.client.indexer().lock();
        self.trees.iter().fold((0, 0), |(leaves, queued), tree| {
            let (tree_leaves, tree_queued) = tree_progress(&rpc, &tree.address);
            (leaves + tree_leaves, queued + tree_queued)
        })
    }

    /// `role`'s wallet after a full sync over every deposit and transaction.
    fn synced_wallet(&self, role: Role) -> Result<Wallet> {
        let keys = &self.actor(role)?.shielded;
        let registry = AssetRegistry::new(
            self.tokens
                .values()
                .map(|token| (token.mint.asset_id, token.mint.asset)),
        )?;
        let mut wallet = Wallet::new(keys.shielded_address()?, registry)?;
        let mut transactions = self.deposits.clone();
        transactions.extend(
            self.client
                .indexer()
                .lock()
                .indexer()
                .transactions()
                .iter()
                .cloned(),
        );
        wallet.sync(
            &KeypairWalletAuthority::new(Address::default(), keys),
            &transactions,
            0,
            DEFAULT_TAG_WINDOW,
        )?;
        Ok(wallet)
    }

    fn assert_unspent(&self, vector: &FunctionalVector) -> Result<()> {
        for (role, expected) in &vector.unspent_after {
            let wallet = self.synced_wallet(*role)?;
            let owner = self.actor(*role)?.shielded.signing_pubkey();
            let spent = |note: &WalletUtxo| {
                self.client
                    .indexer()
                    .lock()
                    .indexer()
                    .is_nullifier_spent(&note.nullifier)
            };
            // Data notes are the runner's to track; see `data_note`.
            let data_notes = self
                .notes
                .values()
                .filter(|note| note.data_hash.is_some() && note.utxo.owner == owner)
                .filter(|note| !spent(note));
            let mut held = Vec::new();
            for note in wallet.unspent().chain(data_notes) {
                held.push(NoteBalance {
                    asset: self.asset_of(&note.utxo.asset)?,
                    amount: note.utxo.amount,
                    ring: false,
                });
            }
            held.sort();
            let expected: Vec<NoteBalance> = expected
                .iter()
                .map(|note| NoteBalance {
                    ring: false,
                    ..note.clone()
                })
                .collect();
            ensure!(
                held == expected,
                "{role} holds {held:?}, expected {expected:?}"
            );
        }
        Ok(())
    }
}

impl Token {
    /// The token account of `role`, or of the harness payer for `None`.
    fn account(&self, role: Option<Role>) -> Result<Pubkey> {
        self.accounts
            .get(&role)
            .copied()
            .ok_or_else(|| anyhow!("no token account for {role:?}"))
    }
}

/// Creates every mint the vector names, with its SPL interface and the token
/// accounts its legs and funding use.
struct TokenSetup<'a> {
    pool: &'a mut Pool,
    actors: &'a BTreeMap<Role, Actor>,
    vector: &'a FunctionalVector,
}

impl TokenSetup<'_> {
    fn create(self) -> Result<BTreeMap<Asset, Token>> {
        let mut used = BTreeSet::new();
        used.extend(self.vector.funding.iter().map(|note| note.asset));
        for step in &self.vector.steps {
            used.extend(step.outputs.iter().map(|output| output.asset));
            used.extend(step.public.iter().map(|leg| leg.asset));
        }
        used.remove(&Asset::Sol);
        let mut tokens = BTreeMap::new();
        if used.is_empty() {
            return Ok(tokens);
        }
        let rpc = &mut self.pool.rpc;
        rpc.ensure_asset_counter(&self.pool.authority)?;
        let harness_payer = rpc.payer.pubkey();
        for asset in used {
            let token_program = match asset {
                Asset::Token2022A => spl_token_2022_interface::ID,
                _ => SprProgramTest::token_program_id(),
            };
            let mint = rpc.create_mint_with_program(token_program)?;
            let (registry, _) =
                rpc.create_spl_interface_with_program(&self.pool.authority, &mint, token_program)?;
            let registry_data = rpc
                .account_data(&registry)
                .ok_or_else(|| anyhow!("SPL asset registry of {mint}"))?;
            let asset_id = SplAssetRegistry::from_account_bytes(&registry_data)
                .map_err(|error| anyhow!("SPL asset registry of {mint}: {error:?}"))?
                .asset_id;

            let mut accounts = BTreeMap::new();
            let payer_account =
                rpc.create_token_account_with_program(&mint, &harness_payer, token_program)?;
            rpc.mint_to_with_program(&mint, &payer_account, TOKEN_SUPPLY, token_program)?;
            accounts.insert(None, payer_account);
            let roles: BTreeSet<Role> = self
                .vector
                .steps
                .iter()
                .flat_map(|step| &step.public)
                .filter(|leg| leg.asset == asset)
                .map(|leg| leg.account)
                .collect();
            for role in roles {
                let owner = actor(self.actors, role)?.solana.pubkey();
                let account =
                    rpc.create_token_account_with_program(&mint, &owner, token_program)?;
                if matches!(role, Role::Funder(_)) {
                    rpc.mint_to_with_program(&mint, &account, TOKEN_SUPPLY, token_program)?;
                }
                accounts.insert(Some(role), account);
            }
            tokens.insert(
                asset,
                Token {
                    mint: Mint::new(mint, asset_id),
                    token_program,
                    accounts,
                },
            );
        }
        Ok(tokens)
    }
}

/// Creates a cache of tree 0 the way an operator does and seats every note a
/// cached input reads, as an earlier merge's write would have. A client
/// transact cannot write a cache, so the runner stands in for that writer.
fn seat_cache(
    rpc: &mut SprProgramTest,
    vector: &FunctionalVector,
    notes: &BTreeMap<String, WalletUtxo>,
) -> Result<Option<SeatedCache>> {
    let cached: Vec<&String> = vector
        .steps
        .iter()
        .flat_map(|step| &step.inputs)
        .filter_map(|slot| match slot {
            InputSlot::Utxo {
                note, cached: true, ..
            } => Some(note),
            _ => None,
        })
        .collect();
    if cached.is_empty() {
        return Ok(None);
    }
    let sponsor = rpc.payer.pubkey();
    let mut tree_id = None;
    let mut slots = BTreeMap::new();
    let mut hashes = Vec::with_capacity(cached.len());
    for (slot, note) in cached.into_iter().enumerate() {
        let held = notes
            .get(note)
            .ok_or_else(|| anyhow!("cached note {note} is not funded"))?;
        ensure!(
            *tree_id.get_or_insert(held.tree_id) == held.tree_id,
            "cached notes span trees"
        );
        slots.insert(note.clone(), u8::try_from(slot)?);
        hashes.push(held.utxo_hash);
    }
    let tree_id = tree_id.ok_or_else(|| anyhow!("no cached note"))?;
    let expires_at = rpc.svm.get_sysvar::<Clock>().unix_timestamp + CACHE_LIFETIME_SECONDS;
    rpc.create_and_send_default_payer_transaction(
        &[CreateCache {
            payer: sponsor,
            data: CreateCacheData {
                write_authority: sponsor,
                nonce: 0,
                tree_id,
                expires_at,
            },
        }
        .instruction()],
        &[],
    )?;
    let (address, _) = pda::cache(&sponsor, 0);
    let mut account = rpc
        .svm
        .get_account(&address)
        .ok_or_else(|| anyhow!("cache account {address}"))?;
    let mut state: CacheAccount = *bytemuck::try_from_bytes(&account.data)
        .map_err(|error| anyhow!("cache account layout: {error}"))?;
    for (seat, hash) in state.utxo_hashes.iter_mut().zip(hashes) {
        *seat = hash;
    }
    account.data = bytemuck::bytes_of(&state).to_vec();
    rpc.svm
        .set_account(address, account)
        .map_err(|error| anyhow!("seat the cache: {error:?}"))?;
    Ok(Some(SeatedCache { address, slots }))
}

fn actor(actors: &BTreeMap<Role, Actor>, role: Role) -> Result<&Actor> {
    actors
        .get(&role)
        .ok_or_else(|| anyhow!("the vector names no {role}"))
}

fn token(tokens: &BTreeMap<Asset, Token>, asset: Asset) -> Result<&Token> {
    tokens
        .get(&asset)
        .ok_or_else(|| anyhow!("no mint for {}", asset.label()))
}

fn uses_second_tree(vector: &FunctionalVector) -> bool {
    vector.funding.iter().any(|note| note.tree == 1)
        || vector.steps.iter().any(|step| {
            step.output_tree == 1
                || step
                    .inputs
                    .iter()
                    .any(|slot| matches!(slot, InputSlot::Address { tree: 1, .. }))
        })
}

/// The smallest in-circuit owner shape holding the step's slots.
fn shape_for(step: &Step) -> Result<Shape> {
    let inputs = step.inputs.len().max(usize::from(step.min_input_slots));
    let outputs = step.outputs.len().max(usize::from(step.min_output_slots));
    CONFIDENTIAL_EDDSA_SHAPES
        .into_iter()
        .find(|shape| shape.n_inputs() >= inputs && shape.n_outputs() >= outputs)
        .ok_or_else(|| anyhow!("no in-circuit owner shape holds {inputs}x{outputs}"))
}
