use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst},
    Arc, Mutex,
};
use std::time::Duration;

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
    let recipients = [NitroPaymentRecipient::new(
        service.clone(),
        payer.pubkey(),
        address,
        false,
        0,
    )];
    for outputs in [
        vec![],
        vec![other],
        vec![rotated],
        vec![other_nullifier],
        vec![address, rotated],
    ] {
        let signed = transaction(payer.pubkey(), &outputs);
        assert!(matches!(
            Submission::new(&signed, payer.pubkey(), &keys).with_nitro_recipients(&recipients, &[]),
            Err(ClientError::NitroDecryption(
                NitroDecryptionError::PaymentRecipientMismatch
            ))
        ));
    }
    let signed = transaction(payer.pubkey(), &[address, other, address]);
    assert!(matches!(
        Submission::new(&signed, payer.pubkey(), &keys)
            .with_nitro_recipients(&[], &[address, other]),
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientsRequired
        ))
    ));
    assert!(matches!(
        Submission::new(&signed, payer.pubkey(), &keys).with_nitro_recipients(&recipients, &[]),
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientMismatch
        ))
    ));
    assert!(Submission::new(&signed, payer.pubkey(), &keys)
        .with_nitro_recipients(&recipients, &[other])
        .is_ok());
    let [first] = recipients;
    let other_owner = Pubkey::new_from_array(other.signing_pubkey.as_ed25519().unwrap());
    let all_recipients = [
        first,
        NitroPaymentRecipient::new(service, other_owner, other, true, 0),
    ];
    let payment = Submission::new(&signed, payer.pubkey(), &keys)
        .with_nitro_recipients(&all_recipients, &[])
        .expect("all targets declared");
    assert_eq!(
        payment.assertion,
        assert_payment_targets(&[
            PaymentTarget {
                owner: payer.pubkey().to_bytes(),
                keys: Some(RegisterData {
                    nullifier_pubkey: address.nullifier_pubkey,
                    viewing_pubkey: *address.viewing_pubkey.as_bytes(),
                }),
            },
            PaymentTarget {
                owner: other_owner.to_bytes(),
                keys: None,
            },
        ])
        .unwrap(),
    );
    let recipients = &all_recipients[..1];
    let same_owner_wrong_keys = transaction(payer.pubkey(), &[address, rotated]);
    assert!(
        Submission::new(&same_owner_wrong_keys, payer.pubkey(), &keys)
            .with_nitro_recipients(recipients, &[rotated])
            .is_err()
    );
}

struct RegistryRpc {
    owner: Pubkey,
    addresses: [ShieldedAddress; 2],
    rotated: AtomicBool,
    foreign_network: AtomicBool,
    blockhash_valid: Mutex<Result<bool, &'static str>>,
    registry_slot: AtomicU64,
    broadcast_slot: AtomicU64,
    blockhash_slot: AtomicU64,
    rotate_on_blockhash_check: AtomicBool,
    broadcasts: AtomicUsize,
    stalled_broadcast: Mutex<Option<Signature>>,
    stall_broadcast: AtomicBool,
    broadcast_started: tokio::sync::Notify,
    confirmations: Mutex<Vec<Signature>>,
    broadcast_reply: Mutex<Result<Signature, &'static str>>,
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

    async fn get_account_with_context(
        &self,
        address: Pubkey,
        min_context_slot: u64,
    ) -> Result<(u64, Option<Account>), ClientError> {
        let configured = self.registry_slot.load(SeqCst);
        let slot = if configured == 0 {
            min_context_slot
        } else {
            configured
        };
        Ok((slot, self.get_account(address).await?))
    }

    async fn blockhash_validity_with_context(
        &self,
        hash: &Hash,
        min_context_slot: u64,
    ) -> Result<(u64, bool), ClientError> {
        let configured = self.blockhash_slot.load(SeqCst);
        let slot = if configured == 0 {
            min_context_slot
        } else {
            configured
        };
        Ok((slot, self.is_blockhash_valid(hash).await?))
    }

    async fn is_blockhash_valid(&self, hash: &Hash) -> Result<bool, ClientError> {
        assert_eq!(hash.as_bytes(), &[1; 32]);
        if self.rotate_on_blockhash_check.swap(false, SeqCst) {
            self.rotated.store(true, SeqCst);
        }
        self.blockhash_valid
            .lock()
            .unwrap()
            .map_err(|message| ClientError::Rpc(message.into()))
    }

    async fn process_transaction_with_context(
        &self,
        transaction: VersionedTransaction,
        min_context_slot: Option<u64>,
    ) -> Result<Signature, ClientError> {
        self.broadcast_slot.store(min_context_slot.unwrap(), SeqCst);
        self.broadcasts.fetch_add(1, SeqCst);
        if self.stall_broadcast.load(SeqCst) {
            *self.stalled_broadcast.lock().unwrap() = transaction.signatures.first().copied();
            self.broadcast_started.notify_one();
            std::future::pending::<()>().await;
        }
        self.broadcast_reply
            .lock()
            .unwrap()
            .map_err(|message| ClientError::Rpc(message.into()))
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.confirmations.lock().unwrap().push(signature);
        Err(ClientError::Rpc("mock confirmation".into()))
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
            blockhash_valid: Mutex::new(Ok(true)),
            registry_slot: AtomicU64::default(),
            broadcast_slot: AtomicU64::default(),
            blockhash_slot: AtomicU64::default(),
            rotate_on_blockhash_check: AtomicBool::default(),
            broadcasts: AtomicUsize::default(),
            stalled_broadcast: Mutex::default(),
            stall_broadcast: AtomicBool::default(),
            broadcast_started: tokio::sync::Notify::new(),
            confirmations: Mutex::default(),
            broadcast_reply: Mutex::new(Err("mock broadcast")),
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
    let submission = || {
        Submission::new(&signed, payer.pubkey(), &keys)
            .with_nitro_recipients(&recipients, &[])
            .unwrap()
    };
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
    let no_sign =
        async |_: &UnsignedMessage| panic!("an invalid payment must not reach the signer");
    client.rpc().rotated.store(true, SeqCst);
    assert!(matches!(
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), no_sign)
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientChanged
        ))
    ));
    client.rpc().rotated.store(false, SeqCst);
    client.rpc().foreign_network.store(true, SeqCst);
    assert!(matches!(
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), no_sign)
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::NetworkMismatch
        ))
    ));
    client.rpc().foreign_network.store(false, SeqCst);
    *client.rpc().blockhash_valid.lock().unwrap() = Ok(false);
    assert!(matches!(
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), no_sign)
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentBlockhashInvalid
        ))
    ));
    *client.rpc().blockhash_valid.lock().unwrap() = Ok(true);
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);

    client.rpc().blockhash_slot.store(10, SeqCst);
    client.rpc().registry_slot.store(9, SeqCst);
    assert!(matches!(
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), no_sign)
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentContextStale
        ))
    ));
    client.rpc().registry_slot.store(20, SeqCst);
    let payment = submission()
        .sign_unsigned(
            client.rpc(),
            unsigned(1),
            async |prepared: &UnsignedMessage| {
                sign_transaction(prepared.message.clone(), &[&payer])
            },
        )
        .await
        .unwrap();
    client.rpc().blockhash_slot.store(19, SeqCst);
    assert!(matches!(
        payment.send(&client).await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentContextStale
        ))
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    client.rpc().registry_slot.store(0, SeqCst);
    client.rpc().blockhash_slot.store(0, SeqCst);

    let signer = RotatingSigner(&payer, &client.rpc().rotated);
    let payment = submission()
        .sign_unsigned(
            client.rpc(),
            unsigned(1),
            async |prepared: &UnsignedMessage| {
                sign_transaction(prepared.message.clone(), &[&signer])
            },
        )
        .await
        .unwrap();
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    assert!(matches!(
        payment.send(&client).await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientChanged
        ))
    ));
    assert!(client.rpc().rotated.load(SeqCst));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);

    client.rpc().rotated.store(false, SeqCst);
    assert!(matches!(
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), async |_: &UnsignedMessage| {
                sign_transaction(unsigned(2).message, &[&payer])
            })
            .await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentMessageChanged
        ))
    ));
    for signatures in [vec![], vec![Signature::default()]] {
        assert!(matches!(
            submission()
                .sign_unsigned(
                    client.rpc(),
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

    let result = submission()
        .sign_unsigned(
            client.rpc(),
            unsigned(1),
            async |prepared: &UnsignedMessage| {
                let signed = sign_transaction(prepared.message.clone(), &[&payer])?;
                client.rpc().foreign_network.store(true, SeqCst);
                Ok(signed)
            },
        )
        .await
        .unwrap()
        .send(&client)
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

    let signed_transaction = sign_transaction(unsigned(1).message, &[&payer]).unwrap();
    let expected = signed_transaction.signatures[0];
    let sign = async || {
        submission()
            .sign_unsigned(client.rpc(), unsigned(1), async |_: &UnsignedMessage| {
                tokio::task::yield_now().await;
                Ok(signed_transaction.clone())
            })
            .await
            .unwrap()
    };
    let send = async || sign().await.send(&client).await;
    let stale_registry = sign().await;
    client.rpc().blockhash_slot.store(10, SeqCst);
    client.rpc().registry_slot.store(9, SeqCst);
    assert!(matches!(
        stale_registry.send(&client).await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentContextStale
        ))
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    client.rpc().registry_slot.store(0, SeqCst);
    client.rpc().blockhash_slot.store(0, SeqCst);
    let expired = sign().await;
    *client.rpc().blockhash_valid.lock().unwrap() = Ok(false);
    assert!(matches!(
        expired.send(&client).await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentBlockhashInvalid
        ))
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    *client.rpc().blockhash_valid.lock().unwrap() = Ok(true);
    let unchecked_hash = sign().await;
    *client.rpc().blockhash_valid.lock().unwrap() = Err("mock blockhash check");
    assert!(
        matches!(unchecked_hash.send(&client).await, Err(ClientError::Rpc(message)) if message == "mock blockhash check")
    );
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    *client.rpc().blockhash_valid.lock().unwrap() = Ok(true);
    let changing_recipient = sign().await;
    client.rpc().rotate_on_blockhash_check.store(true, SeqCst);
    assert!(matches!(
        changing_recipient.send(&client).await,
        Err(ClientError::NitroDecryption(
            NitroDecryptionError::PaymentRecipientChanged
        ))
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 0);
    client.rpc().rotated.store(false, SeqCst);
    client.rpc().blockhash_slot.store(18, SeqCst);
    client.rpc().registry_slot.store(19, SeqCst);
    let ready = sign().await;
    client.rpc().blockhash_slot.store(20, SeqCst);
    client.rpc().registry_slot.store(21, SeqCst);
    assert!(matches!(
        ready.send(&client).await,
        Err(ClientError::NitroPaymentSend { signature, source })
            if signature == expected && matches!(*source, ClientError::Rpc(ref message) if message == "mock broadcast")
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 1);
    assert_eq!(client.rpc().broadcast_slot.load(SeqCst), 21);
    client.rpc().blockhash_slot.store(21, SeqCst);
    *client.rpc().broadcast_reply.lock().unwrap() = Ok(Signature::default());
    assert!(matches!(
        send().await,
        Err(ClientError::NitroPaymentSend { signature, source })
            if signature == expected && matches!(*source, ClientError::TransactionSignatureMismatch)
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 2);
    assert!(client.rpc().confirmations.lock().unwrap().is_empty());

    *client.rpc().broadcast_reply.lock().unwrap() = Ok(expected);
    assert!(matches!(
        send().await,
        Err(ClientError::NitroPaymentSend { signature, source })
            if signature == expected && matches!(*source, ClientError::Rpc(ref message) if message == "mock confirmation")
    ));
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 3);
    assert_eq!(*client.rpc().confirmations.lock().unwrap(), [expected]);

    let payment = sign().await;
    let recorded = payment.signature();
    assert_eq!(recorded, expected);
    assert_eq!(payment.blockhash().as_bytes(), &[1; 32]);
    assert_eq!(payment.last_valid_block_height(), 1);
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 3);
    client.rpc().stall_broadcast.store(true, SeqCst);
    tokio::select! {
        _ = payment.send(&client) => panic!("the send is still in flight"),
        result = tokio::time::timeout(Duration::from_secs(1), client.rpc().broadcast_started.notified()) => {
            result.unwrap();
        }
    }
    assert_eq!(
        *client.rpc().stalled_broadcast.lock().unwrap(),
        Some(recorded)
    );
    assert_eq!(client.rpc().broadcasts.load(SeqCst), 4);
    assert_eq!(*client.rpc().confirmations.lock().unwrap(), [expected]);
}
