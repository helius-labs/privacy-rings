mod common;

use common::{keypair, wallet_utxo};
use solana_signature::Signature;
use spr_event::OutputDataEncoding;
use spr_keypair::{ShieldedKeypair, ViewingKey};
use spr_transaction::{
    decrypt_spendable,
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    serialization::{confidential::Confidential, verifiable::Verifiable},
    AssetRegistry, EncryptedScheme, EncryptionMode, LocalShieldedKeys, Mint, OutputContext,
    OutputSlot, ShieldedTransaction,
};

fn transfer(
    mode: EncryptionMode,
) -> (
    ShieldedKeypair,
    ShieldedKeypair,
    SppProofInputs,
    ShieldedTransaction,
) {
    let sender = keypair(81);
    let recipient = keypair(82);
    let input = wallet_utxo(&sender, Mint::SOL, 100, 2, 1);
    let mut transaction = ConfidentialTransaction::new(
        vec![input],
        sender.shielded_address().unwrap().solana_address().unwrap(),
    )
    .unwrap()
    .with_output_tree_id(2)
    .unwrap()
    .with_encryption_mode(mode);
    transaction
        .transfer_sol(&recipient.shielded_address().unwrap(), 42)
        .unwrap();
    let prepared = transaction
        .finalize(&sender.shielded_address().unwrap())
        .unwrap()
        .encrypt_with_keys(&sender)
        .unwrap();
    let indexed = ShieldedTransaction {
        slot: 9,
        tx_signature: Signature::from([9; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(
            spr_keypair::X25519Pubkey::from_bytes(prepared.external_data.tx_viewing_pk).unwrap(),
        ),
        salt: Some(prepared.external_data.salt),
        output_slots: prepared
            .external_data
            .outputs
            .iter()
            .zip(&prepared.external_data.resolved_owner_tags)
            .enumerate()
            .map(|(index, (output, view_tag))| OutputSlot {
                view_tag: *view_tag,
                output_context: OutputContext {
                    hash: output.utxo_hash,
                    tree_id: 2,
                    leaf_index: index as u64,
                },
                payload: output.data.clone().unwrap(),
            })
            .collect(),
        messages: vec![],
        nullifiers: prepared
            .input_utxos
            .iter()
            .map(|input| input.nullifier)
            .collect(),
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    (sender, recipient, prepared, indexed)
}

#[test]
fn recipient_sender_and_retired_keys_decode_the_selected_mode() {
    for mode in [EncryptionMode::Confidential, EncryptionMode::Verifiable] {
        let (sender, recipient, prepared, indexed) = transfer(mode);
        let assets = AssetRegistry::default();
        let received =
            decrypt_spendable(&recipient, std::slice::from_ref(&indexed), &assets).unwrap();
        let recipient_utxo = received.utxos().next().unwrap();
        let change = decrypt_spendable(&sender, std::slice::from_ref(&indexed), &assets).unwrap();
        assert_eq!(
            (
                received.utxos().count(),
                recipient_utxo.utxo.amount,
                change.utxos().next().unwrap().utxo.amount
            ),
            (1, 42, 58),
        );
        assert_eq!(
            recipient_utxo.nullifier,
            recipient
                .nullifier(&recipient_utxo.utxo_hash, &recipient_utxo.utxo.blinding)
                .unwrap()
        );

        let tx_key = sender
            .get_transaction_viewing_key(indexed.nullifiers.first().unwrap())
            .unwrap();
        let recipient_slot = indexed
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == recipient_utxo.utxo_hash)
            .unwrap();
        let slot_index = recipient_utxo.slot_index;
        let expected_output = prepared
            .output_utxos
            .iter()
            .find(|output| output.owner_address == Some(recipient.shielded_address().unwrap()))
            .unwrap();
        let (scheme, plaintext) = match recipient_slot.output_data().unwrap() {
            OutputDataEncoding::Encrypted(blob) => {
                let (scheme, body) = blob.split_first().unwrap();
                (
                    *scheme,
                    Confidential::decrypt_with_tx_key(
                        &tx_key,
                        body,
                        indexed.salt.unwrap(),
                        slot_index,
                    )
                    .unwrap(),
                )
            }
            OutputDataEncoding::VerifiablyEncrypted(blob) => {
                let (scheme, body) = blob.split_first().unwrap();
                (
                    *scheme,
                    Verifiable::decrypt_with_tx_key(
                        &tx_key,
                        body,
                        indexed.salt.unwrap(),
                        slot_index,
                    )
                    .unwrap(),
                )
            }
            OutputDataEncoding::Plaintext(_) => panic!("expected ciphertext"),
        };
        assert_eq!(
            (scheme, plaintext.amount, plaintext.blinding),
            (
                match mode {
                    EncryptionMode::Confidential => EncryptedScheme::Confidential,
                    EncryptionMode::Verifiable => EncryptedScheme::Verifiable,
                }
                .as_byte(),
                42,
                expected_output.blinding
            ),
        );

        let current = ViewingKey::from_bytes(&[83; 32]);
        let mut rotated_address = recipient.shielded_address().unwrap();
        rotated_address.viewing_pubkey = current.pubkey();
        let rotated = LocalShieldedKeys::new(
            rotated_address,
            vec![current, recipient.viewing_key.clone()],
            recipient.nullifier_key.clone(),
        )
        .unwrap();
        assert_eq!(
            decrypt_spendable(&rotated, &[indexed], &assets).unwrap(),
            received
        );
    }
}

#[test]
fn verifiable_decode_rejects_wrong_context_framing_and_output_hash() {
    let (_, recipient, _, indexed) = transfer(EncryptionMode::Verifiable);
    let assets = AssetRegistry::default();
    let received = decrypt_spendable(&recipient, std::slice::from_ref(&indexed), &assets).unwrap();
    let utxo_hash = received.utxos().next().unwrap().utxo_hash;
    let mut single = indexed.clone();
    // Preserve the physical output index while hiding the other ciphertexts;
    // moving the recipient slot would itself change the KDF context.
    for slot in &mut single.output_slots {
        if slot.output_context.hash != utxo_hash {
            slot.payload.clear();
        }
    }
    let mut mutations = Vec::new();
    let mut wrong = single.clone();
    wrong.salt = None;
    mutations.push(wrong);
    let mut wrong = single.clone();
    wrong.tx_viewing_pk = None;
    mutations.push(wrong);
    let mut wrong = single.clone();
    wrong.salt = Some([255; 16]);
    mutations.push(wrong);
    let mut wrong = single.clone();
    wrong.tx_viewing_pk = Some(keypair(84).viewing_pubkey());
    mutations.push(wrong);
    let mut wrong = single.clone();
    wrong.output_slots.insert(
        0,
        OutputSlot {
            view_tag: [0; 32],
            output_context: OutputContext {
                hash: [0; 32],
                tree_id: 2,
                leaf_index: 0,
            },
            payload: vec![],
        },
    );
    mutations.push(wrong);
    for mutation in 0..5 {
        let mut wrong = single.clone();
        let slot = wrong
            .output_slots
            .iter_mut()
            .find(|slot| slot.output_context.hash == utxo_hash)
            .unwrap();
        let OutputDataEncoding::VerifiablyEncrypted(mut blob) = slot.output_data().unwrap() else {
            panic!("expected verifiable output");
        };
        match mutation {
            0 => {
                *blob.last_mut().unwrap() ^= 1;
            }
            1 => {
                slot.output_context.hash = [0; 32];
            }
            2 => {
                blob.truncate(12);
            }
            3 => {
                *blob.first_mut().unwrap() = EncryptedScheme::Confidential.as_byte();
            }
            4 => {}
            _ => unreachable!(),
        }
        slot.payload = borsh::to_vec(&if mutation == 4 {
            OutputDataEncoding::Encrypted(blob)
        } else {
            OutputDataEncoding::VerifiablyEncrypted(blob)
        })
        .unwrap();
        mutations.push(wrong);
    }
    for wrong in mutations {
        assert_eq!(
            decrypt_spendable(&recipient, &[wrong], &assets)
                .unwrap()
                .utxos()
                .count(),
            0
        );
    }
    assert_eq!(
        decrypt_spendable(&keypair(85), &[single], &assets)
            .unwrap()
            .utxos()
            .count(),
        0
    );
}
