use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    Arc,
};

use solana_account::Account;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_signer::SignerError;
use solana_transaction::versioned::VersionedTransaction;
use spr_keypair::{NullifierKey, ShieldedKeypair, ViewingKey};
use spr_transaction::{
    instructions::transact::{ExternalData, SppProofInputs},
    utxo::SppProofOutputUtxo,
};
use spr_user_registry_interface::{
    user_record_pda, user_registry_program_id, MergeEncryptionScheme, UserRecord,
};

use super::*;
use crate::{
    indexer::AsyncSprIndexer,
    nitro_policy::{NitroTrust, UnixNitroCheckpointStore},
    prover::AsyncProverClient,
    rpc::{compile_message, ComputeBudgetConfig},
    SignedPrivateTransaction,
};

fn decryption(directory: &tempfile::TempDir) -> NitroDecryptionService {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/nitro-policy.json")).unwrap();
    NitroDecryptionService::new(
        Arc::new(NitroTrust::from_json(&serde_json::to_vec(&fixture["trust"]).unwrap()).unwrap()),
        Arc::new(UnixNitroCheckpointStore::open(directory.path()).unwrap()),
    )
    .unwrap()
}

fn transaction(payer: Pubkey, recipients: &[ShieldedAddress]) -> SignedPrivateTransaction {
    SignedPrivateTransaction {
        transaction: SppProofInputs {
            payer,
            input_utxos: Vec::new(),
            output_utxos: recipients
                .iter()
                .map(|address| SppProofOutputUtxo {
                    owner_address: Some(*address),
                    ..Default::default()
                })
                .collect(),
            output_tree_id: 0,
            blinding_seed: [9; 32],
            external_data: ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![]),
            cache_accounts: Default::default(),
        },
        settlement_transfers: Vec::new(),
    }
}

#[test]
fn attachment_requires_exact_keys_on_every_output_for_the_owner() {
    let directory = tempfile::tempdir().unwrap();
    let service = decryption(&directory);
    let payer = Keypair::new();
    let keys = ShieldedKeypair::from_keypair(&payer).unwrap();
    let address = keys.shielded_address().unwrap();
    let rotated = ShieldedAddress {
        viewing_pubkey: ViewingKey::new().pubkey(),
        ..address
    };
    let other_nullifier = ShieldedAddress {
        nullifier_pubkey: NullifierKey::from_secret([42; 31]).pubkey().unwrap(),
        ..address
    };
    let other = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    let recipients = [NitroPaymentRecipient::new(service, payer.pubkey(), address)];
    for outputs in [
        vec![],
        vec![other],
        vec![rotated],
        vec![other_nullifier],
        vec![address, rotated],
    ] {
        let signed = transaction(payer.pubkey(), &outputs);
        assert!(matches!(
            Submission::new(&signed, payer.pubkey(), &keys).with_nitro_recipients(&recipients),
            Err(ClientError::NitroDecryption(
                NitroDecryptionError::PaymentRecipientMismatch
            ))
        ));
    }
    let signed = transaction(payer.pubkey(), &[address, other, address]);
    assert!(Submission::new(&signed, payer.pubkey(), &keys)
        .with_nitro_recipients(&recipients)
        .is_ok());
}

struct RegistryRpc {
    owner: Pubkey,
    addresses: [ShieldedAddress; 2],
    rotated: AtomicBool,
    foreign_network: AtomicBool,
    broadcasts: AtomicUsize,
}

#[async_trait::async_trait]
impl AsyncRpc for RegistryRpc {
    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        let genesis = if self.foreign_network.load(SeqCst) {
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
        } else {
            "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
        };
        Ok(genesis.parse::<Hash>().unwrap().to_bytes())
    }

    async fn get_account(&self, address: Pubkey) -> Result<Option<Account>, ClientError> {
        let (pda, bump) = user_record_pda(&self.owner);
        assert_eq!(address, pda);
        let keys = self.addresses[usize::from(self.rotated.load(SeqCst))];
        let record = UserRecord {
            owner: self.owner.to_bytes().into(),
            bump,
            nullifier_pubkey: keys.nullifier_pubkey,
            viewing_pubkey: *keys.viewing_pubkey.as_bytes(),
            merge_encryption: MergeEncryptionScheme::Disabled,
        };
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&borsh::to_vec(&record).unwrap());
        data.resize(UserRecord::SIZE, 0);
        Ok(Some(Account {
            lamports: 1,
            data,
            owner: user_registry_program_id(),
            ..Default::default()
        }))
    }

    async fn process_transaction(&self, _: VersionedTransaction) -> Result<Signature, ClientError> {
        self.broadcasts.fetch_add(1, SeqCst);
        Err(ClientError::Rpc("mock broadcast".into()))
    }
}

struct RotatingSigner<'a>(&'a Keypair, &'a AtomicBool);

impl Signer for RotatingSigner<'_> {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.0.try_pubkey()
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.1.store(true, SeqCst);
        self.0.try_sign_message(message)
    }

    fn is_interactive(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn the_signed_payment_is_checked_before_broadcast() {
    let directory = tempfile::tempdir().unwrap();
    let service = decryption(&directory);
    let payer = Keypair::new();
    let keys = ShieldedKeypair::from_keypair(&payer).unwrap();
    let address = keys.shielded_address().unwrap();
    let rotated = ShieldedAddress {
        viewing_pubkey: ViewingKey::new().pubkey(),
        ..address
    };
    let client = AsyncSprClient::new(
        RegistryRpc {
            owner: payer.pubkey(),
            addresses: [address, rotated],
            rotated: AtomicBool::default(),
            foreign_network: AtomicBool::default(),
            broadcasts: AtomicUsize::default(),
        },
        AsyncSprIndexer::new("http://127.0.0.1:1"),
        AsyncProverClient::local(),
    );
    let recipient = service
        .resolve_recipient(client.rpc(), payer.pubkey())
        .await
        .unwrap();
    assert_eq!(recipient.address(), address);
    let signed = transaction(payer.pubkey(), &[recipient.address()]);
    let recipients = [recipient];
    let submission = Submission::new(&signed, payer.pubkey(), &keys)
        .with_nitro_recipients(&recipients)
        .unwrap();
    let unsigned = |blockhash| UnsignedMessage {
        message: compile_message(
            &payer.pubkey(),
            &[],
            Hash::new_from_array([blockhash; 32]),
            ComputeBudgetConfig::for_instruction_count(1),
        )
        .unwrap(),
        last_valid_block_height: 1,
    };
    let signer = RotatingSigner(&payer, &client.rpc().rotated);
    assert!(matches!(
        submission
            .send_unsigned(&client, unsigned(1), async |prepared: &UnsignedMessage| {
                sign_transaction(prepared.message.clone(), &[&signer])
            })
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientChanged
        ))
    ));
    assert!(client.rpc().rotated.load(SeqCst));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);

    client.rpc().rotated.store(false, SeqCst);
    assert!(matches!(
        submission
            .send_unsigned(&client, unsigned(1), async |_: &UnsignedMessage| {
                sign_transaction(unsigned(2).message, &[&payer])
            })
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentMessageChanged
        ))
    ));
    for signatures in [vec![], vec![Signature::default()]] {
        assert!(matches!(
            submission
                .send_unsigned(
                    &client,
                    unsigned(1),
                    async move |prepared: &UnsignedMessage| {
                        Ok(VersionedTransaction {
                            message: prepared.message.clone(),
                            signatures,
                        })
                    }
                )
                .await,
            Err(ClientError::SolanaTransactionSigning(_))
        ));
    }
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);

    let result = submission
        .send_unsigned(&client, unsigned(1), async |prepared: &UnsignedMessage| {
            let signed = sign_transaction(prepared.message.clone(), &[&payer])?;
            client.rpc().foreign_network.store(true, SeqCst);
            Ok(signed)
        })
        .await;
    assert!(matches!(
        result,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::NetworkMismatch
        ))
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    assert!(matches!(
        service
            .resolve_recipient(client.rpc(), payer.pubkey())
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::NetworkMismatch
        ))
    ));
    client.rpc().foreign_network.store(false, SeqCst);

    assert!(matches!(
        submission
            .send_unsigned(&client, unsigned(1), async |prepared: &UnsignedMessage| {
                tokio::task::yield_now().await;
                sign_transaction(prepared.message.clone(), &[&payer])
            })
            .await,
        Err(ClientError::Rpc(message)) if message == "mock broadcast"
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 1);
}
