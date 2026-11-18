use std::collections::{BTreeMap, BTreeSet, HashSet};

use solana_address::Address;
use spr_event::{split_merge_output_body, OutputDataEncoding};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{
    constants::BLINDING_LEN, shielded::ShieldedAddress, x25519::X25519_PUBKEY_LEN, KeypairError,
    NullifierKey,
};

use crate::{
    asset::{AssetRegistry, Balances, Mint},
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    instructions::merge::MergeOutputPlaintext,
    keys::{DecryptLabel, DecryptRequest, DeriveRequest, ShieldedKeys, TransactionKeyRequest},
    ring::{RingCodec, RingOpening},
    serialization::{
        confidential::Confidential, plaintext::PlaintextTransfer, proofless::Proofless,
        scheme::EncryptedScheme, OwnerCx, UtxoSerialization,
    },
    utxo::{Utxo, WalletUtxo},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecryptionResult {
    pub utxos: Vec<WalletUtxo>,
    pub spent_nullifiers: HashSet<[u8; 32]>,
    /// Asset ids read from decoded outputs that the asset registry does not
    /// know. Those outputs are left out. The sender wrote the id and nothing on
    /// chain checks it, so it is unverified: register the assets that exist
    /// and decrypt again, and the commitment decides.
    pub unknown_asset_ids: BTreeSet<u64>,
    /// Mints named by authenticated deposits or merge outputs this wallet owns
    /// that the asset registry has no id for. Those outputs are left out;
    /// register the mints and decrypt again.
    pub unknown_mints: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendableDecryptionResult {
    pub balances: Balances,
    pub utxos_with_data: Vec<WalletUtxo>,
    /// As on [`DecryptionResult`].
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`].
    pub unknown_mints: BTreeSet<Address>,
}

impl SpendableDecryptionResult {
    /// Every spendable UTXO: the balances' UTXOs, then the data-bearing ones.
    pub fn utxos(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.balances
            .assets
            .iter()
            .flat_map(|balance| &balance.utxos)
            .chain(&self.utxos_with_data)
    }

    /// The ring notes of `utxos_with_data` by ring program.
    pub fn ring_balances(&self) -> BTreeMap<Address, Balances> {
        let mut rings: BTreeMap<Address, Vec<WalletUtxo>> = BTreeMap::new();
        for utxo in &self.utxos_with_data {
            if let Some(ring) = utxo.utxo.ring_program_id {
                rings.entry(ring).or_default().push(utxo.clone());
            }
        }
        rings
            .into_iter()
            .map(|(ring, utxos)| (ring, utxos.into_iter().collect()))
            .collect()
    }

    fn utxos_mut(&mut self) -> impl Iterator<Item = &mut WalletUtxo> {
        self.balances
            .assets
            .iter_mut()
            .flat_map(|balance| &mut balance.utxos)
            .chain(&mut self.utxos_with_data)
    }

    /// Attach to every spendable UTXO the transaction viewing key of a
    /// transaction that spends it first, derived for the holder's viewing key
    /// in one [`ShieldedKeys::transaction_keys`] request, so encrypting that
    /// transaction needs no further key request.
    pub fn with_transaction_keys<K: ShieldedKeys + ?Sized>(
        mut self,
        shielded_keys: &K,
    ) -> Result<Self, TransactionError> {
        let viewing_pubkey = shielded_keys.address()?.viewing_pubkey;
        let mut utxos: Vec<&mut WalletUtxo> = self.utxos_mut().collect();
        let requests: Vec<TransactionKeyRequest> = utxos
            .iter()
            .map(|utxo| TransactionKeyRequest {
                viewing_pubkey,
                first_nullifier: utxo.nullifier,
            })
            .collect();
        if requests.is_empty() {
            return Ok(self);
        }
        let keys = shielded_keys.transaction_keys(&requests)?;
        if keys.len() != requests.len() {
            return Err(TransactionError::IncompleteDerivation {
                got: keys.len(),
                want: requests.len(),
            });
        }
        for (utxo, key) in utxos.iter_mut().zip(keys) {
            utxo.tx_viewing_key = Some(*key.secret_bytes());
        }
        Ok(self)
    }

    /// Stamp every spendable UTXO with the newest output tree the indexer
    /// reported on the pages it came from (`output_tree_id`), so a
    /// transaction spending one appends its outputs there by default. `None`
    /// means the indexer named no unpaused tree.
    #[must_use]
    pub fn with_latest_tree_id(mut self, latest_tree_id: Option<u16>) -> Self {
        for utxo in self.utxos_mut() {
            utxo.latest_tree_id = latest_tree_id;
        }
        self
    }
}

/// Decrypts and verifies notes against the supplied transactions.
pub fn decrypt_spendable<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<SpendableDecryptionResult, TransactionError> {
    let decrypted = decrypt(shielded_keys, transactions, assets)?;
    verify_spendable(shielded_keys, &decrypted)
}

/// Returns decoded candidates without commitment or spend verification.
pub fn decrypt<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<DecryptionResult, TransactionError> {
    let mut decrypted = DecryptionResult::default();
    decrypted.extend(shielded_keys, transactions, assets)?;
    Ok(decrypted)
}

impl DecryptionResult {
    /// Adds the candidates of `transactions`, decrypting only those, so a
    /// client that reads its transactions in rounds decrypts each one once. A
    /// merge output decrypts from its own transaction like any other output.
    /// Left unchanged on error.
    pub fn extend<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
    ) -> Result<(), TransactionError> {
        self.extend_opened(shielded_keys, transactions, assets, &[])?;
        Ok(())
    }

    /// [`Self::extend`] plus what `ring` opens in its own events, returning the
    /// openings under an unregistered mint at asset id 0.
    pub fn extend_with_ring<K: ShieldedKeys + ?Sized, R: RingCodec + ?Sized>(
        &mut self,
        shielded_keys: &K,
        events: &[ShieldedTransaction],
        assets: &AssetRegistry,
        ring: &R,
    ) -> Result<Vec<WalletUtxo>, R::Error> {
        let openings = events
            .iter()
            .map(|event| {
                if event.ring_program_id == Some(ring.ring_program_id()) {
                    ring.open(event)
                } else {
                    Ok(Vec::new())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.extend_opened(shielded_keys, events, assets, &openings)?)
    }

    /// `openings` pairs with `transactions` by position, a missing entry opens nothing.
    fn extend_opened<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
        openings: &[Vec<RingOpening>],
    ) -> Result<Vec<WalletUtxo>, TransactionError> {
        let address = shielded_keys.address()?;
        let mut found = Vec::new();
        let mut unregistered = Vec::new();
        let mut unknown_asset_ids = BTreeSet::new();
        let mut unknown_mints = BTreeSet::new();
        for (index, tx) in transactions.iter().enumerate() {
            let openings = openings.get(index).map_or(&[][..], Vec::as_slice);
            for (position, slot) in tx.output_slots.iter().enumerate() {
                let slot_index =
                    u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
                let published = |utxo, data_hash, ring_data_hash| WalletUtxo {
                    utxo,
                    nullifier_pubkey: address.nullifier_pubkey,
                    utxo_hash: slot.output_context.hash,
                    nullifier: [0; 32],
                    tx_viewing_key: None,
                    data_hash,
                    ring_data_hash,
                    tree_id: slot.output_context.tree_id,
                    leaf_index: slot.output_context.leaf_index,
                    latest_tree_id: None,
                    slot: tx.slot,
                    tx_signature: tx.tx_signature,
                    slot_index,
                };
                for opening in openings
                    .iter()
                    .filter(|opening| opening.slot_index == slot_index)
                {
                    let mut note = WalletUtxo {
                        nullifier_pubkey: opening.nullifier_pubkey,
                        ..published(
                            Utxo {
                                owner: address.signing_pubkey,
                                asset: Mint::new(opening.mint, 0),
                                amount: opening.amount,
                                blinding: opening.blinding,
                                ring_program_id: tx.ring_program_id,
                                data: opening.data.clone(),
                            },
                            opening.data_hash,
                            opening.ring_data_hash,
                        )
                    };
                    if !opens(&address, &note)? {
                        continue;
                    }
                    // The commitment binds the mint address, never its registry id.
                    match assets.asset_id(&opening.mint) {
                        Ok(asset_id) => {
                            note.utxo.asset.asset_id = asset_id;
                            found.push(note);
                        }
                        Err(_) => {
                            unknown_mints.insert(opening.mint);
                            unregistered.push(note);
                        }
                    }
                }
                let decoded =
                    match decode_slot(shielded_keys, &address, tx, slot, slot_index, assets) {
                        Ok(Some(decoded)) => decoded,
                        Ok(None) => continue,
                        // An asset the registry lacks leaves one output out and
                        // is reported, rather than failing the whole scan.
                        // Deposits and merges name their mint; every other
                        // output carries a registry id.
                        Err(TransactionError::UnknownAsset(asset_id)) => {
                            unknown_asset_ids.insert(asset_id);
                            continue;
                        }
                        Err(TransactionError::UnknownMint(mint)) => {
                            unknown_mints.insert(mint);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                found.extend(
                    decoded
                        .utxos
                        .into_iter()
                        .map(|utxo| published(utxo, decoded.data_hash, decoded.ring_data_hash)),
                );
            }
        }
        assign_nullifiers(shielded_keys, found.iter_mut().chain(&mut unregistered))?;
        let mut utxos = self.utxos.clone();
        utxos.extend(found);
        utxos.sort_by(WalletUtxo::chain_order);
        self.utxos = utxos;
        self.spent_nullifiers.extend(
            transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied()),
        );
        self.unknown_asset_ids.extend(unknown_asset_ids);
        self.unknown_mints.extend(unknown_mints);
        Ok(unregistered)
    }
}

/// Skips unresolved, mismatched and spent notes; spend status covers the supplied batch.
pub fn verify_spendable<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<SpendableDecryptionResult, TransactionError> {
    Ok(verify_owned(shielded_keys, decrypted)?.spendable())
}

/// The UTXOs a wallet owns among a [`DecryptionResult`], spent or not, as
/// [`verify_owned`] returns them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedUtxos {
    /// In the order the [`DecryptionResult`] holds them.
    pub utxos: Vec<WalletUtxo>,
    /// The nullifiers of the spent ones.
    pub spent: HashSet<[u8; 32]>,
    /// As on [`DecryptionResult`].
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`].
    pub unknown_mints: BTreeSet<Address>,
}

impl OwnedUtxos {
    /// The unspent ones, as [`verify_spendable`] returns them, for a caller
    /// that keeps the spent ones too: it asks the key holder nothing more.
    pub fn spendable(&self) -> SpendableDecryptionResult {
        let (mut utxos_with_data, default_ring): (Vec<_>, Vec<_>) = self
            .utxos
            .iter()
            .filter(|utxo| !self.spent.contains(&utxo.nullifier))
            .cloned()
            .partition(|utxo| {
                utxo.utxo.data.utxo_data().is_some()
                    || utxo.utxo.data.ring_data().is_some()
                    || utxo.data_hash.is_some()
                    || utxo.ring_data_hash.is_some()
                    || utxo.utxo.ring_program_id.is_some()
            });
        utxos_with_data.sort_by(WalletUtxo::chain_order);
        SpendableDecryptionResult {
            balances: default_ring.into_iter().collect(),
            utxos_with_data,
            unknown_asset_ids: self.unknown_asset_ids.clone(),
            unknown_mints: self.unknown_mints.clone(),
        }
    }
}

/// The UTXOs of `decrypted` this wallet owns, spent or not. Each commitment is
/// recomputed from the decoded fields and must match the published one; a
/// commitment counts once, and every nullifier is derived again rather than
/// taken from `decrypted`. [`verify_spendable`] is this without the spent ones.
pub fn verify_owned<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<OwnedUtxos, TransactionError> {
    let address = shielded_keys.address()?;
    let mut claimed = HashSet::new();
    let mut verified = Vec::new();
    for input in &decrypted.utxos {
        if opens(&address, input)? && claimed.insert(input.utxo_hash) {
            verified.push(input.clone());
        }
    }
    assign_nullifiers(shielded_keys, &mut verified)?;
    let spent = verified
        .iter()
        .map(|utxo| utxo.nullifier)
        .filter(|nullifier| decrypted.spent_nullifiers.contains(nullifier))
        .collect();
    Ok(OwnedUtxos {
        utxos: verified,
        spent,
        unknown_asset_ids: decrypted.unknown_asset_ids.clone(),
        unknown_mints: decrypted.unknown_mints.clone(),
    })
}

fn opens(address: &ShieldedAddress, input: &WalletUtxo) -> Result<bool, TransactionError> {
    let nullifier_pubkey = input.nullifier_pubkey;
    let held = nullifier_pubkey == address.nullifier_pubkey
        || (nullifier_pubkey == ZERO_NULLIFIER_PUBKEY && input.utxo.ring_program_id.is_some());
    if input.utxo.owner != address.signing_pubkey
        || !held
        || (input.utxo.data.utxo_data().is_some() && input.data_hash.is_none())
        || (input.utxo.data.ring_data().is_some() && input.ring_data_hash.is_none())
    {
        return Ok(false);
    }
    let hash = input.utxo.hash(
        &input.nullifier_pubkey,
        &input.data_hash.unwrap_or_default(),
        &input.ring_data_hash.unwrap_or_default(),
        input.tree_id,
    )?;
    Ok(hash == input.utxo_hash)
}

/// One slot's decoded contents. `data_hash` and `ring_data_hash` are the ones
/// the commitment was built with; only the proofless rail publishes them.
struct DecodedSlot {
    utxos: Vec<Utxo>,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
}

fn decode_slot<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    slot_index: u32,
    assets: &AssetRegistry,
) -> Result<Option<DecodedSlot>, TransactionError> {
    let Some(output_data) = slot.output_data() else {
        return Ok(None);
    };
    let owner_cx = OwnerCx {
        owner: address.signing_pubkey,
        assets,
        ring_program_id: None,
        first_nullifier: tx.nullifiers.first().copied(),
    };

    match output_data {
        OutputDataEncoding::Plaintext(blob) => {
            let Some((&scheme_byte, body)) = blob.split_first() else {
                return Ok(None);
            };
            let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                return Ok(None);
            };
            match scheme {
                EncryptedScheme::Proofless => {
                    let Ok(plaintext) = Proofless::deserialize(body) else {
                        return Ok(None);
                    };
                    if plaintext.owner != address.owner_hash()? {
                        return Ok(None);
                    }
                    let data_hash = plaintext.data_hash;
                    let ring_data_hash = plaintext.ring_data_hash;
                    Ok(
                        rebuilt(Proofless::into_utxos(plaintext, &owner_cx))?.map(|utxos| {
                            DecodedSlot {
                                utxos,
                                data_hash,
                                ring_data_hash,
                            }
                        }),
                    )
                }
                EncryptedScheme::PlaintextTransfer => {
                    let Ok(plaintext) = PlaintextTransfer::deserialize(body) else {
                        return Ok(None);
                    };
                    Ok(
                        rebuilt(PlaintextTransfer::into_utxos(plaintext, &owner_cx))?.map(
                            |utxos| DecodedSlot {
                                utxos,
                                data_hash: None,
                                ring_data_hash: None,
                            },
                        ),
                    )
                }
                _ => Ok(None),
            }
        }
        OutputDataEncoding::Encrypted(blob) => {
            let Some((&scheme_byte, body)) = blob.split_first() else {
                return Ok(None);
            };
            let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                return Ok(None);
            };
            // A ring merge publishes its ciphertext unverified: the ring merge
            // proof does not bind it, so only the commitment check accepts it.
            if scheme == EncryptedScheme::Merge {
                return decode_merge(shielded_keys, address, tx, slot, &blob, owner_cx, true);
            }
            let (ciphertext, viewing_pubkeys) = match scheme {
                EncryptedScheme::Confidential | EncryptedScheme::RingConfidential => {
                    let Ok(viewing_pubkey) = Confidential::embedded_viewing_pk(body) else {
                        return Ok(None);
                    };
                    if !shielded_keys
                        .viewing_public_keys()
                        .contains(&viewing_pubkey)
                    {
                        return Ok(None);
                    }
                    let Some((_, ciphertext)) = body.split_at_checked(X25519_PUBKEY_LEN) else {
                        return Ok(None);
                    };
                    (ciphertext, vec![viewing_pubkey])
                }
                _ => return Ok(None),
            };
            let (Some(tx_viewing_pubkey), Some(salt)) = (tx.tx_viewing_pk, tx.salt) else {
                return Ok(None);
            };
            let requests: Vec<_> = viewing_pubkeys
                .into_iter()
                .map(|viewing_pubkey| DecryptRequest {
                    ciphertext,
                    viewing_pubkey,
                    tx_viewing_pubkey,
                    salt,
                    slot_index,
                    label: DecryptLabel::Utxo,
                })
                .collect();
            let Some(plaintexts) = trial_decrypt(shielded_keys, &requests)? else {
                return Ok(None);
            };
            for bytes in plaintexts {
                let utxos = match scheme {
                    EncryptedScheme::Confidential | EncryptedScheme::RingConfidential => {
                        let Ok(plaintext) = Confidential::deserialize(&bytes) else {
                            continue;
                        };
                        Confidential::into_utxos(plaintext, &owner_cx)
                    }
                    _ => return Ok(None),
                };
                let Some(utxos) = rebuilt(utxos)? else {
                    continue;
                };
                return Ok(Some(DecodedSlot {
                    utxos,
                    data_hash: None,
                    ring_data_hash: None,
                }));
            }
            Ok(None)
        }
        OutputDataEncoding::VerifiablyEncrypted(blob) => {
            decode_merge(shielded_keys, address, tx, slot, &blob, owner_cx, false)
        }
    }
}

/// A merge output publishes its amount and mint encrypted under a key the
/// owner derives from the nullifier secret and the first nullifier, so the
/// owner rebuilds the output from the merge transaction alone. A default merge
/// proof binds that ciphertext, whichever inputs the merger chose; a ring merge
/// (`ring`) publishes it unverified. The cipher is unauthenticated: a merge of
/// another wallet, or a wrong ring merge ciphertext, decrypts to noise, which
/// the plaintext range check or the commitment rejects.
fn decode_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    blob: &[u8],
    owner_cx: OwnerCx,
    ring: bool,
) -> Result<Option<DecodedSlot>, TransactionError> {
    let Some((&scheme_byte, body)) = blob.split_first() else {
        return Ok(None);
    };
    if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Merge) {
        return Ok(None);
    }
    let Some((ring_data_hash, encrypted)) = split_merge_output_body(body) else {
        return Ok(None);
    };
    // A ring merge leads with its output ring data hash, names its ring program
    // and is published unverified; a slot missing any of these is not a merge
    // output.
    if ring_data_hash.is_some() != ring || tx.ring_program_id.is_some() != ring {
        return Ok(None);
    }
    let Some(&first_nullifier) = tx.nullifiers.first() else {
        return Ok(None);
    };
    let requests = [
        DeriveRequest::MergeOutputKey { first_nullifier },
        DeriveRequest::MergeOutputBlinding { first_nullifier },
    ];
    let derived = shielded_keys.derive(&requests)?;
    let [key, blinding] = <[[u8; 32]; 2]>::try_from(derived).map_err(|derived| {
        TransactionError::IncompleteDerivation {
            got: derived.len(),
            want: requests.len(),
        }
    })?;
    let Ok(plaintext) = MergeOutputPlaintext::decrypt(encrypted, &key) else {
        return Ok(None);
    };
    // Only the mint address enters the commitment. Resolve its registry ID
    // after authentication so unverified ciphertext cannot request backfills.
    let mut utxo = plaintext.into_utxo(
        owner_cx.owner,
        Mint::new(plaintext.mint, 0),
        blinding,
        tx.ring_program_id,
    );
    let context = &slot.output_context;
    let hash = utxo.hash(
        &address.nullifier_pubkey,
        &[0; 32],
        &ring_data_hash.copied().unwrap_or_default(),
        context.tree_id,
    )?;
    if hash != context.hash {
        return Ok(None);
    }
    utxo.asset = owner_cx.assets.mint(&plaintext.mint)?;
    Ok(Some(DecodedSlot {
        utxos: vec![utxo],
        data_hash: None,
        ring_data_hash: ring_data_hash.copied(),
    }))
}

/// A sender-chosen plaintext that rebuilds no note skips its slot, except a registry miss.
fn rebuilt(
    utxos: Result<Vec<Utxo>, TransactionError>,
) -> Result<Option<Vec<Utxo>>, TransactionError> {
    match utxos {
        Ok(utxos) => Ok(Some(utxos)),
        Err(error @ (TransactionError::UnknownAsset(_) | TransactionError::UnknownMint(_))) => {
            Err(error)
        }
        Err(_) => Ok(None),
    }
}

/// `None` when no viewing key can open the requests.
fn trial_decrypt<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    requests: &[DecryptRequest<'_>],
) -> Result<Option<Vec<Vec<u8>>>, TransactionError> {
    if requests.is_empty() {
        return Ok(None);
    }
    let plaintexts = match shielded_keys.decrypt(requests) {
        Ok(plaintexts) => plaintexts,
        // The sender picks `tx_viewing_pk`, a low-order one opens under no key.
        Err(TransactionError::Keypair(KeypairError::NonContributoryKey)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if plaintexts.len() != requests.len() {
        return Err(TransactionError::IncompleteDecryption {
            got: plaintexts.len(),
            want: requests.len(),
        });
    }
    Ok(Some(plaintexts))
}

fn assign_nullifiers<'a, K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    utxos: impl IntoIterator<Item = &'a mut WalletUtxo>,
) -> Result<(), TransactionError> {
    let (zero_keyed, mut utxos): (Vec<_>, Vec<_>) = utxos
        .into_iter()
        .partition(|input| input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY);
    // The zero secret is public, its nullifier needs no holder.
    let zero_key = NullifierKey::from_secret([0; BLINDING_LEN]);
    for input in zero_keyed {
        input.nullifier = zero_key.nullifier(&input.utxo_hash, &input.utxo.blinding)?;
    }
    if utxos.is_empty() {
        return Ok(());
    }
    let requests: Vec<_> = utxos
        .iter()
        .map(|input| DeriveRequest::Nullifier {
            utxo_hash: input.utxo_hash,
            blinding: input.utxo.blinding,
        })
        .collect();
    let nullifiers = shielded_keys.derive(&requests)?;
    if nullifiers.len() != utxos.len() {
        return Err(TransactionError::IncompleteDerivation {
            got: nullifiers.len(),
            want: utxos.len(),
        });
    }
    for (input, nullifier) in utxos.iter_mut().zip(nullifiers) {
        input.nullifier = nullifier;
    }
    Ok(())
}
