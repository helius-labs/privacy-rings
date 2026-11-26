mod common;

use common::{keypair, wallet_utxo};
use solana_signature::Signature;
use spr_event::OutputDataEncoding;
use spr_keypair::{x25519::X25519_PUBKEY_LEN, ShieldedKeypair, ViewingKey};
use spr_transaction::{
    decrypt_spendable,
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    serialization::{confidential::Confidential, poseidon_kdf::PoseidonKdf},
    AssetRegistry, DecodeCx, EncryptedScheme, EncryptionMode, LocalShieldedKeys, Mint,
    OutputContext, OutputSlot, ShieldedTransaction, SppProofOutputUtxo, TransactionError,
    UtxoSerialization,
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
    .unwrap();
    transaction
        .add_output_utxo(
            SppProofOutputUtxo::new(Mint::SOL, 42, recipient.shielded_address().unwrap())
                .unwrap()
                .with_encryption_mode(mode),
        )
        .unwrap();
    let prepared = transaction
        .finalize(&sender.shielded_address().unwrap())
        .unwrap()
        .encrypt_with_keys(&sender)
        .unwrap();
    let indexed = publication(&prepared);
    (sender, recipient, prepared, indexed)
}

fn publication(prepared: &SppProofInputs) -> ShieldedTransaction {
    ShieldedTransaction {
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
    }
}

#[test]
fn recipient_sender_and_retired_keys_decode_the_selected_mode() {
    for mode in [EncryptionMode::Hkdf, EncryptionMode::PoseidonKdf] {
        let (sender, recipient, prepared, indexed) = transfer(mode);
        let assets = AssetRegistry::default();
        let received =
            decrypt_spendable(&recipient, std::slice::from_ref(&indexed), &assets).unwrap();
        let recipient_utxo = received.utxos().next().unwrap();
        let change = decrypt_spendable(&sender, std::slice::from_ref(&indexed), &assets).unwrap();
        let change_utxo = change.utxos().next().unwrap();
        let change_slot = indexed
            .output_slots
            .iter()
            .find(|slot| slot.output_context.hash == change_utxo.utxo_hash)
            .unwrap();
        let OutputDataEncoding::Encrypted(change_blob) = change_slot.output_data().unwrap() else {
            panic!("generated change must use confidential encryption");
        };
        assert_eq!(
            change_blob.first(),
            Some(&EncryptedScheme::Confidential.as_byte())
        );
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
        let OutputDataEncoding::Encrypted(blob) = recipient_slot.output_data().unwrap() else {
            panic!("expected ordinary encrypted framing");
        };
        let (&scheme, body) = blob.split_first().unwrap();
        let plaintext = match mode {
            EncryptionMode::Hkdf => {
                Confidential::decrypt_with_tx_key(&tx_key, body, indexed.salt.unwrap(), slot_index)
            }
            EncryptionMode::PoseidonKdf => {
                PoseidonKdf::decrypt_with_tx_key(&tx_key, body, indexed.salt.unwrap(), slot_index)
            }
        }
        .unwrap();
        assert_eq!(
            (scheme, plaintext.amount, plaintext.blinding),
            (
                match mode {
                    EncryptionMode::Hkdf => EncryptedScheme::Confidential,
                    EncryptionMode::PoseidonKdf => EncryptedScheme::PoseidonKdf,
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
fn direct_poseidon_kdf_decode_rejects_a_replaced_embedded_recipient_key() {
    let (_, recipient, _, indexed) = transfer(EncryptionMode::PoseidonKdf);
    let (slot_index, slot) = indexed
        .output_slots
        .iter()
        .enumerate()
        .find(|(_, slot)| {
            matches!(
                slot.output_data(),
                Some(OutputDataEncoding::Encrypted(blob))
                    if blob.first() == Some(&EncryptedScheme::PoseidonKdf.as_byte())
            )
        })
        .unwrap();
    let OutputDataEncoding::Encrypted(blob) = slot.output_data().unwrap() else {
        panic!("expected Poseidon-KDF output");
    };
    let (&scheme, body) = blob.split_first().unwrap();
    let cx = DecodeCx::for_slot(&recipient.viewing_key, &indexed, slot_index as u32);
    let plaintext = PoseidonKdf::decode(body, &cx).unwrap();
    assert_eq!(
        (plaintext.amount, plaintext.asset_id),
        (42, Mint::SOL.asset_id)
    );

    let replacement = keypair(88).viewing_pubkey();
    let mut changed_body = body.to_vec();
    changed_body
        .get_mut(..X25519_PUBKEY_LEN)
        .unwrap()
        .copy_from_slice(replacement.as_bytes());
    assert_eq!(
        changed_body.get(X25519_PUBKEY_LEN..),
        body.get(X25519_PUBKEY_LEN..)
    );
    assert_eq!(
        (
            PoseidonKdf::decrypt(&changed_body, &cx),
            PoseidonKdf::decode(&changed_body, &cx)
        ),
        (
            Err(TransactionError::RecipientViewingKeyMismatch),
            Err(TransactionError::RecipientViewingKeyMismatch)
        ),
    );

    let mut changed_blob = vec![scheme];
    changed_blob.extend_from_slice(&changed_body);
    let mut changed_transaction = indexed.clone();
    changed_transaction
        .output_slots
        .get_mut(slot_index)
        .unwrap()
        .payload = borsh::to_vec(&OutputDataEncoding::Encrypted(changed_blob)).unwrap();
    assert_eq!(
        decrypt_spendable(
            &recipient,
            &[changed_transaction],
            &AssetRegistry::default()
        )
        .unwrap()
        .utxos()
        .count(),
        0,
    );
}

#[test]
fn mixed_output_modes_preserve_slot_indices_and_commitments() {
    let sender = keypair(86);
    let recipient = keypair(87);
    let sender_address = sender.shielded_address().unwrap();
    let recipient_address = recipient.shielded_address().unwrap();
    for modes in [
        [
            EncryptionMode::Hkdf,
            EncryptionMode::PoseidonKdf,
            EncryptionMode::Hkdf,
        ],
        [
            EncryptionMode::PoseidonKdf,
            EncryptionMode::Hkdf,
            EncryptionMode::PoseidonKdf,
        ],
    ] {
        let input = wallet_utxo(&sender, Mint::SOL, 100, 2, 1);
        let mut transaction =
            ConfidentialTransaction::new(vec![input], sender_address.solana_address().unwrap())
                .unwrap()
                .with_output_tree_id(2)
                .unwrap();
        for (amount, mode) in [11, 22, 33].into_iter().zip(modes) {
            transaction
                .add_output_utxo(
                    SppProofOutputUtxo::new(Mint::SOL, amount, recipient_address)
                        .unwrap()
                        .with_encryption_mode(mode),
                )
                .unwrap();
        }
        let tx_key = sender
            .get_transaction_viewing_key(transaction.first_nullifier())
            .unwrap();
        let finalized = transaction.finalize(&sender_address).unwrap();
        assert_eq!(
            finalized
                .output_utxos()
                .iter()
                .map(|output| output.encryption_mode)
                .collect::<Vec<_>>(),
            modes
                .into_iter()
                .chain([EncryptionMode::Hkdf])
                .collect::<Vec<_>>(),
        );
        let prepared = finalized.encrypt_with_viewing_key(&tx_key).unwrap();
        let indexed = publication(&prepared);
        for ((output, slot), mode) in prepared
            .output_utxos
            .iter()
            .zip(&indexed.output_slots)
            .zip(modes)
        {
            let expected_scheme = match mode {
                EncryptionMode::Hkdf => EncryptedScheme::Confidential,
                EncryptionMode::PoseidonKdf => EncryptedScheme::PoseidonKdf,
            };
            let OutputDataEncoding::Encrypted(blob) = slot.output_data().unwrap() else {
                panic!("output must use ordinary encrypted framing");
            };
            assert_eq!(
                (output.encryption_mode, blob.first()),
                (mode, Some(&expected_scheme.as_byte()))
            );
            let opposite_mode = match mode {
                EncryptionMode::Hkdf => EncryptionMode::PoseidonKdf,
                EncryptionMode::PoseidonKdf => EncryptionMode::Hkdf,
            };
            assert_eq!(
                output.clone().with_encryption_mode(opposite_mode).hash(2),
                output.hash(2)
            );
        }
        let received = decrypt_spendable(
            &recipient,
            std::slice::from_ref(&indexed),
            &AssetRegistry::default(),
        )
        .unwrap();
        let change = decrypt_spendable(&sender, &[indexed], &AssetRegistry::default()).unwrap();
        assert_eq!(
            (
                received
                    .utxos()
                    .map(|utxo| (utxo.utxo.amount, utxo.slot_index))
                    .collect::<Vec<_>>(),
                change
                    .utxos()
                    .map(|utxo| utxo.utxo.amount)
                    .collect::<Vec<_>>(),
            ),
            (vec![(11, 0), (22, 1), (33, 2)], vec![34]),
        );
    }
}

#[test]
fn poseidon_kdf_decode_rejects_wrong_context_framing_and_output_hash() {
    let (_, recipient, _, indexed) = transfer(EncryptionMode::PoseidonKdf);
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
        let OutputDataEncoding::Encrypted(mut blob) = slot.output_data().unwrap() else {
            panic!("expected Poseidon-KDF output");
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
            OutputDataEncoding::VerifiablyEncrypted(blob)
        } else {
            OutputDataEncoding::Encrypted(blob)
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
