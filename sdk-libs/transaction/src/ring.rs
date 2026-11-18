//! Core keeps ownership, commitments, balances and input selection.

use solana_address::Address;
use spr_keypair::shielded::ShieldedAddress;

use crate::{
    error::{RingPaymentRefusal, TransactionError},
    indexer_types::ShieldedTransaction,
    instructions::transact::SppProofInputs,
    utxo::SppProofInputUtxo,
    Blinding, Data, Mint, WalletUtxo,
};

/// An opening counts only once core rebuilds its published commitment.
pub trait RingCodec {
    type Error: From<TransactionError>;

    fn ring_program_id(&self) -> Address;

    fn open(&self, event: &ShieldedTransaction) -> Result<Vec<RingOpening>, Self::Error>;
}

/// Owner, ring, asset id and published commitment come from core, never from the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOpening {
    pub slot_index: u32,
    /// The holder's key or `ZERO_NULLIFIER_PUBKEY`, core refuses any other.
    pub nullifier_pubkey: [u8; 32],
    pub mint: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub data: Data,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
pub struct RingPaymentTerms<'a> {
    pub source: ShieldedAddress,
    pub recipient: ShieldedAddress,
    pub asset: Mint,
    pub amount: u64,
    pub ring_program_id: Address,
    pub reserved: &'a [WalletUtxo],
}

/// Input notes come from the reservation, never from the ring.
pub fn checked_ring_payment(
    proof_inputs: &SppProofInputs,
    terms: &RingPaymentTerms<'_>,
) -> Result<SppProofInputs, TransactionError> {
    let mut unspent: Vec<&WalletUtxo> = terms.reserved.iter().collect();
    let mut input_utxos = Vec::with_capacity(proof_inputs.input_utxos.len());
    for (index, input) in proof_inputs.input_utxos.iter().enumerate() {
        input_utxos.push(if !input.is_dummy() {
            let position = unspent
                .iter()
                .position(|note| note.nullifier == input.nullifier)
                .ok_or(RingPaymentRefusal::UnreservedInput { index })?;
            SppProofInputUtxo::from(unspent.swap_remove(position))
        } else if input.is_compact() {
            SppProofInputUtxo::compact(input.tree_id)?
        } else {
            SppProofInputUtxo::dummy_with_blinding(input.utxo.blinding, input.tree_id)?
        });
    }
    if !unspent.is_empty() {
        return Err(RingPaymentRefusal::UnspentReservation.into());
    }
    let mut paid = 0u128;
    for (index, output) in proof_inputs.output_utxos.iter().enumerate() {
        let Some(owner) = output.owner_address else {
            continue;
        };
        if output.ring_program_id != Some(terms.ring_program_id) {
            return Err(RingPaymentRefusal::OutputOutsideRing { index }.into());
        }
        if owner == terms.source {
            continue;
        }
        if owner != terms.recipient {
            return Err(RingPaymentRefusal::ForeignOutputOwner { index }.into());
        }
        if output.asset != terms.asset {
            return Err(RingPaymentRefusal::RecipientAsset { index }.into());
        }
        paid += u128::from(output.amount);
    }
    if terms.recipient != terms.source && paid != u128::from(terms.amount) {
        return Err(RingPaymentRefusal::RecipientAmount.into());
    }
    if !proof_inputs.external_data.interface_transfers.is_empty() {
        return Err(RingPaymentRefusal::InterfaceTransfer.into());
    }
    Ok(SppProofInputs {
        input_utxos,
        output_utxos: proof_inputs.output_utxos.clone(),
        blinding_seed: proof_inputs.blinding_seed,
        output_tree_id: proof_inputs.output_tree_id,
        external_data: proof_inputs.external_data.clone(),
        payer: proof_inputs.payer,
        cache_accounts: proof_inputs.cache_accounts,
    })
}
