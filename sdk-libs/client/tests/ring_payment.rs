#[path = "common/input.rs"]
mod input;

use std::{
    collections::HashSet,
    future::{ready, Future},
};

use futures::executor::block_on;
use input::wallet_utxo;
use num_bigint::BigUint;
use solana_address::Address;
use spr_client::{
    ClientError, OwnerAuthorization, ProofAuthority, ProofInputUtxo, RingAuthorizer, RingPayment,
    RingPaymentWallet, RingTransferRequest, RingTransfers, TransferInput,
};
use spr_keypair::{shielded::ShieldedAddress, ShieldedKeypair, SigningKey};
use spr_transaction::{
    instructions::transact::{SettlementTransfer, SppProofInputs},
    keys::{ShieldedKeys, TransactionKeyRequest},
    utxo::SppProofInputUtxo,
    Data, Mint, RingPaymentRefusal, SpendableDecryptionResult, TransactionError, Utxo, WalletUtxo,
};

const RING: Address = Address::new_from_array([42; 32]);

struct Ring<F>(F);

impl<F, T> RingTransfers for Ring<F>
where
    F: Fn(RingTransferRequest<'_>) -> Result<T, ClientError>,
    T: Send,
{
    type Error = ClientError;
    type Prepared = T;

    fn ring_program_id(&self) -> Address {
        RING
    }

    fn prepare(
        &self,
        request: RingTransferRequest<'_>,
    ) -> impl Future<Output = Result<T, ClientError>> + Send {
        ready((self.0)(request))
    }
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn recipient() -> ShieldedAddress {
    keypair(8).shielded_address().unwrap()
}

fn note(owner: &ShieldedKeypair, nonce: u8) -> WalletUtxo {
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 100,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    wallet_utxo(utxo, &owner.nullifier_key, 0, u64::from(nonce), None, None)
}

fn spendable(notes: impl IntoIterator<Item = WalletUtxo>) -> SpendableDecryptionResult {
    SpendableDecryptionResult {
        balances: notes.into_iter().collect(),
        ..Default::default()
    }
}

fn payment(owner: &ShieldedKeypair) -> RingPayment {
    RingPayment {
        payer: owner.shielded_address().unwrap().solana_address().unwrap(),
        recipient: recipient(),
        asset: Mint::SOL,
        amount: 30,
    }
}

/// Pays 30 of note 1 into `RING` with `signer` signing inside the proof.
fn pay<T: Send>(
    owner: &ShieldedKeypair,
    signer: Option<&SigningKey>,
    prepare: impl Fn(RingTransferRequest<'_>) -> Result<T, ClientError>,
) -> Result<T, ClientError> {
    let wallet = RingPaymentWallet {
        spendable: &spendable([note(owner, 1)]),
        keys: owner,
        authority: owner,
        owner: signer,
        excluded: &HashSet::new(),
    };
    block_on(payment(owner).prepare(&Ring(prepare), wallet))
}

fn honest(
    request: RingTransferRequest<'_>,
) -> Result<(SppProofInputs, RingAuthorizer<'_>), ClientError> {
    let RingTransferRequest {
        mut transaction,
        payment,
        keys,
        authorizer,
        ..
    } = request;
    transaction.transfer_with_ring(
        &payment.recipient,
        payment.asset,
        payment.amount,
        Some(RING),
    )?;
    Ok((transaction.encrypt(&keys)?, authorizer))
}

fn refusal<T>(result: Result<T, ClientError>) -> Option<RingPaymentRefusal> {
    match result {
        Err(ClientError::Transaction(TransactionError::RingPaymentRefused(refusal))) => {
            Some(refusal)
        }
        _ => None,
    }
}

#[test]
fn the_owner_signs_the_message_hash_of_a_payment_whose_change_stays_in_the_ring() {
    let owner = keypair(7);
    let (inputs, authorization) = pay(&owner, Some(&owner.signing_key), |request| {
        assert_eq!(request.authorizer.owner(), Some(owner.signing_pubkey()));
        let (inputs, authorizer) = honest(request)?;
        let authorization = authorizer.authorize(&inputs)?;
        Ok((inputs, authorization))
    })
    .unwrap();

    let Some(OwnerAuthorization::Prepared {
        owner: signer,
        signature,
    }) = authorization
    else {
        panic!("an in-proof owner gets a prepared signature");
    };
    assert_eq!(signer, owner.signing_pubkey());
    assert!(signer.verify_message(&inputs.message_hash().unwrap(), &signature));
    let outputs: Vec<_> = inputs
        .output_utxos
        .iter()
        .filter_map(|output| Some((output.owner_address?, output.amount, output.ring_program_id)))
        .collect();
    assert_eq!(
        outputs,
        [
            (recipient(), 30, Some(RING)),
            (owner.shielded_address().unwrap(), 70, Some(RING)),
        ]
    );
}

#[test]
fn no_signature_for_an_output_redirected_to_a_third_party() {
    let owner = keypair(7);
    let third_party = keypair(9).shielded_address().unwrap();
    let signed = pay(&owner, Some(&owner.signing_key), |request| {
        let (mut inputs, authorizer) = honest(request)?;
        inputs.output_utxos[0].owner_address = Some(third_party);
        Ok(authorizer.authorize(&inputs)?)
    });
    assert_eq!(
        refusal(signed),
        Some(RingPaymentRefusal::ForeignOutputOwner { index: 0 })
    );
}

#[test]
fn no_signature_for_change_kept_outside_the_ring() {
    let owner = keypair(7);
    let signed = pay(&owner, Some(&owner.signing_key), |request| {
        let (mut inputs, authorizer) = honest(request)?;
        let change = &mut inputs.output_utxos[1];
        assert_eq!(change.owner_address, Some(owner.shielded_address()?));
        change.ring_program_id = None;
        Ok(authorizer.authorize(&inputs)?)
    });
    assert_eq!(
        refusal(signed),
        Some(RingPaymentRefusal::OutputOutsideRing { index: 1 })
    );
}

#[test]
fn no_signature_for_an_input_core_did_not_reserve() {
    let owner = keypair(7);
    let unreserved = note(&owner, 2);
    let signed = pay(&owner, Some(&owner.signing_key), |request| {
        let (mut inputs, authorizer) = honest(request)?;
        inputs.input_utxos[0] = (&unreserved).into();
        Ok(authorizer.authorize(&inputs)?)
    });
    assert_eq!(
        refusal(signed),
        Some(RingPaymentRefusal::UnreservedInput { index: 0 })
    );
}

#[test]
fn no_signature_for_a_payment_carrying_an_interface_transfer() {
    let owner = keypair(7);
    let signed = pay(&owner, Some(&owner.signing_key), |request| {
        let (mut inputs, authorizer) = honest(request)?;
        inputs
            .external_data
            .interface_transfers
            .push(SettlementTransfer::Sol {
                is_deposit: false,
                amount: 30,
                user_sol_account: RING,
            });
        Ok(authorizer.authorize(&inputs)?)
    });
    assert_eq!(refusal(signed), Some(RingPaymentRefusal::InterfaceTransfer));
}

#[test]
fn without_an_owner_valid_inputs_get_no_signature_and_tampered_ones_are_refused() {
    let owner = keypair(7);
    let third_party = keypair(9).shielded_address().unwrap();
    let (valid, tampered) = pay(&owner, None, |request| {
        assert_eq!(request.authorizer.owner(), None);
        let (mut inputs, authorizer) = honest(request)?;
        let valid = authorizer.authorize(&inputs)?;
        inputs.output_utxos[0].owner_address = Some(third_party);
        Ok((
            valid,
            authorizer.authorize(&inputs).map_err(ClientError::from),
        ))
    })
    .unwrap();
    assert!(valid.is_none());
    assert_eq!(
        refusal(tampered),
        Some(RingPaymentRefusal::ForeignOutputOwner { index: 0 })
    );
}

#[test]
fn reserved_keys_answer_only_for_reserved_nullifiers() {
    let owner = keypair(7);
    let unreserved = SppProofInputUtxo::from(&note(&owner, 2));
    pay(&owner, Some(&owner.signing_key), |request| {
        let reserved = request.transaction.inputs()[0].clone();
        let key_request = |input: &SppProofInputUtxo| {
            [TransactionKeyRequest {
                viewing_pubkey: owner.viewing_pubkey(),
                first_nullifier: input.nullifier,
            }]
        };
        assert!(request
            .keys
            .transaction_keys(&key_request(&reserved))
            .is_ok());
        assert_eq!(
            request
                .keys
                .transaction_keys(&key_request(&unreserved))
                .err(),
            Some(TransactionError::RingKeyWithheld)
        );

        let mut inputs = [transfer_input(&reserved), transfer_input(&unreserved)];
        assert!(matches!(
            request.keys.complete_inputs(&mut inputs),
            Err(ClientError::Transaction(TransactionError::RingKeyWithheld))
        ));
        request.keys.complete_inputs(&mut inputs[..1])?;
        assert!(inputs[0].nullifier_secret.is_some());
        Ok(())
    })
    .unwrap();
}

#[test]
fn reserved_keys_do_not_complete_an_unreserved_note_flagged_as_padding() {
    let owner = keypair(7);
    let unreserved = SppProofInputUtxo::from(&note(&owner, 2));
    pay(&owner, None, |request| {
        let mut inputs = [TransferInput {
            is_dummy: BigUint::from(1u8),
            ..transfer_input(&unreserved)
        }];
        assert!(matches!(
            request.keys.complete_inputs(&mut inputs),
            Err(ClientError::Transaction(TransactionError::RingKeyWithheld))
        ));
        assert!(inputs[0].nullifier_secret.is_none());
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_excluded_note_is_never_selected() {
    let owner = keypair(7);
    let (held, free) = (note(&owner, 1), note(&owner, 2));
    let spendable = spendable([held.clone(), free.clone()]);
    let selected = |excluded: &HashSet<[u8; 32]>| {
        let ring = Ring(|request: RingTransferRequest<'_>| {
            Ok(request
                .transaction
                .inputs()
                .iter()
                .map(|input| input.nullifier)
                .collect::<Vec<_>>())
        });
        let wallet = RingPaymentWallet {
            spendable: &spendable,
            keys: &owner,
            authority: &owner,
            owner: None,
            excluded,
        };
        block_on(payment(&owner).prepare(&ring, wallet))
    };
    assert_eq!(
        selected(&HashSet::from([held.nullifier])).unwrap(),
        [free.nullifier]
    );
    assert!(matches!(
        selected(&HashSet::from([held.nullifier, free.nullifier])),
        Err(ClientError::Transaction(
            TransactionError::SpendNeedsExcludedUtxos { amount: 30 }
        ))
    ));
}

fn transfer_input(utxo: &SppProofInputUtxo) -> TransferInput {
    TransferInput {
        utxo: ProofInputUtxo::try_from(utxo).unwrap(),
        is_dummy: BigUint::ZERO,
        state_path_elements: Vec::new(),
        state_path_index: BigUint::ZERO,
        nullifier_low_value: BigUint::ZERO,
        nullifier_next_value: BigUint::ZERO,
        nullifier_low_path_elements: Vec::new(),
        nullifier_low_path_index: BigUint::ZERO,
        tree_slot: BigUint::ZERO,
        nullifier: BigUint::from_bytes_be(&utxo.nullifier),
        owner_pk_hash: BigUint::ZERO,
        nullifier_secret: None,
    }
}
