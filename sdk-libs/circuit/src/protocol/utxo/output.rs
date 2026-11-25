use super::Utxo;
use crate::{CircuitError, Field, UtxoOwner, hash_bytes};
use alloc::vec::Vec;
use spr_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};

#[derive(Clone, Debug)]
pub struct Output {
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub amount: u64,
    pub data_hash: Field,
    pub data: Option<Vec<u8>>,
    pub empty_if_zero: bool,
}
impl Output {
    pub fn is_zero(&self) -> bool {
        self.empty_if_zero && self.amount == 0
    }
    pub fn hash(&self, empty: bool, blinding: Field, tree_id: u16) -> Result<Field, CircuitError> {
        self.hash_on(None, empty, blinding, tree_id)
    }
    pub(in crate::protocol) fn hash_on(
        &self,
        ring_program_id: Option<&Field>,
        empty: bool,
        blinding: Field,
        tree_id: u16,
    ) -> Result<Field, CircuitError> {
        let ring_program_id = match ring_program_id {
            Some(ring_program_id) => {
                if empty {
                    Field::zero()
                } else {
                    *ring_program_id
                }
            }
            None => Field::zero(),
        };
        let utxo = Utxo {
            domain: if empty { DUMMY_DOMAIN } else { UTXO_DOMAIN },
            owner: self.owner,
            asset: self.asset,
            amount: self.amount,
            blinding,
            data_hash: self.data_hash,
            ring_program_id,
            tree_id,
            ..Utxo::default()
        };
        let owner = if empty {
            Field::zero()
        } else {
            self.owner.hash()?
        };
        let asset = if empty {
            Field::zero()
        } else {
            hash_bytes(&self.asset)?
        };
        utxo.hash_with(&owner, &asset)
    }
}
