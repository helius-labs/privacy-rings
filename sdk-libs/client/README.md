# Clients

A client owns the three services a private transaction needs: the Solana
RPC (`R`), the indexer (`I`) and the prover.

## Blocking and async

`AsyncSprClient<R, I>` is the client; `SprClient<R, I>` is the same
client for blocking callers, run on a Tokio runtime it owns, over a blocking
`R` and `I` lifted onto the blocking pool by `Blocking`. There is one
implementation of everything; the blocking client runs it to completion.

```rust
let policy = TeePolicy::from_file_json(&std::fs::read_to_string(policy_path)?)?;
let client = SprClient::from_urls(rpc, indexer_url, prover_url, Some(policy))?;
// AsyncSprClient::from_urls takes the same arguments.
```

or from the services: `SprClient::new(rpc, indexer, prover)` with a
`SprIndexer` and a `ProverClient`, `AsyncSprClient::new` with their
`async` counterparts. `from_urls` accepts https, or http to loopback only;
`check_service_url` is that check for a caller building its own services.
The fourth argument to both URL constructors (including
`from_urls_allowing_insecure_http`) is the prover's policy. Pass `None` for
loopback development; remote proving without a policy fails before HTTP.

Use the blocking client from plain threads or inside a multi-thread runtime,
as `solana_rpc_client`'s blocking client. Inside a `current_thread` runtime
(a default `#[tokio::main]` or `#[tokio::test]`) every call fails with
`ClientError::BlockingInsideRuntime`; use the `async` client there. A
generic helper over the blocking client bounds its RPC with `BlockingRpc`
and its indexer with `BlockingIndexer`.

## Your own HTTP client

`spr_api::HttpClient` and `BlockingHttpClient` carry one request and answer
with the server's response, nothing more: routes, retries, polling, timeouts
and TEE encryption stay with the client, so the transport is not trusted with
any of them. `SprApi::with_client`, `ProverClient::with_client` and
`AsyncProverClient::with_client` take an implementation; `HttpResponse`
carries the headers because a TEE prover answers with ciphertext. Give a
blocking client an HTTP client of its own rather than a clone shared with
another runtime.

Without the `reqwest` feature neither crate links reqwest and only
`with_client` builds a client; `solana-rpc` still links it through
`solana-rpc-client`, so a wallet that wants none brings its own `Rpc` too.

## Standalone decryption

`nitro_policy::NitroPolicyReader` fetches the current policy from two
independently owned S3 buckets named in the wallet's shipped trust pins. Both
heads need the pinned release quorum and two of the three custody policy
approvals over the ordered bucket, region and owner pair. The signed pair
must match the wallet's pins. The mirror may hold the primary's exact
predecessor during an update. The wallet pins the exact policy digest at its minimum sequence and
requires the immediate successor to name that digest. Both heads are required
before the SDK trusts the endpoint, executable
hash, custody epoch and PCR0–4 for any replica.

The reader commits the revision to a durable checkpoint before returning a
replica. An observed head at the stored sequence must match its digest. An
immediate successor must link to it. The custody floor can only rise and
recovery-only mode is permanent. A signed revocation advances the checkpoint and returns no replica.
The reader also keeps its latest accepted checkpoint in memory. Removing or
restoring an older file during the reader's lifetime cannot reopen an older
policy. A restarted reader uses the durable checkpoint and shipped pins.
`UnixNitroCheckpointStore` uses an application-owned directory on a local
filesystem. Reads and writes return a storage error if another process holds
the lock for a second, or if the lock or checkpoint is a symbolic link or
other nonregular file. Other platforms call `NitroPolicyUpdate::advances`
inside their store transaction and persist `checkpoint()` before returning success.

Use `NitroDecryptionService::resolve_recipient` for sends. The resolver uses
service keys after a successful registry miss and matching Solana genesis
hash. It checks the registry again before returning those keys. Reusing an
attested boot for a payment requires reading both signed policy heads.

Build each output with `recipient.address()` and pass the resolved recipients
to `Submission::with_nitro_recipients`. It checks that every output to an
attached owner uses the resolved keys. Its `send` and `send_sync` methods resolve
the recipients again after signing and before broadcast. A changed registration,
changed keys, or a payment refusal aborts the send. Use `send_with_signer` or
`send_with_signer_sync` with an external signer. Return the signed transaction
from the signing callback so the SDK can check its message and recipients
before it broadcasts.

Use `NitroDecryptionService::open` with the owner's Solana signer to recover notes
under the service keys. The returned handle implements `ShieldedKeys` for
`UtxoScan` and `ProofAuthority` for spending. Blocking callers can use
`resolve_recipient_sync` and `open_sync`.

The client checks the current checkpoint before each attestation probe and
before caching the verified boot. It attests with a fresh challenge and encrypts
the request to its attested transport key. A decrypt signature binds the
Solana network, release, batch, one-time response key and an exclusive deadline
within the verified session. The client verifies both published heads before
prompting the signer, before sending the signed request and before opening the
authenticated reply. A revoked, superseded or unavailable policy stops the
exchange. The approval deadline bounds those reads and the replica response.
The enclave checks the deadline before returning a reply. The client
verifies the boot signature, request and ciphertext digests, and deadline
before opening it. The 60-second attestation window starts with the policy
fetch and ends when either elapsed or wall time reaches its deadline. A stalled
checkpoint read cannot start a probe beyond that window. Policy or certificate
expiry can end it earlier. A stalled synchronous signer holds the client's
signer slot until it returns. An unsigned lookup can refresh once if another
client supersedes its accepted policy during connection. A rollback fails
immediately. Retryable exchanges drop the failed session, including on the
last attempt. HTTP 429 reaches the caller and preserves the
session. A recovery-only release permits opening existing notes and
rejects new payment lookups. [Test invariants](tests/NITRO.md)

## Proving and submitting

```rust
let signature = Submission::new(&signed, fee_payer, &authority)
    .send_sync(&client, &[&fee_payer_keypair])?;   // async: .send(&client, ..).await
```

proves, signs, sends and waits until the transaction is confirmed and
indexed. `finish_unsigned_sync` / `finish_unsigned` stop at the unsigned
message, for a fee payer whose key lives elsewhere. The message carries a
blockhash fetched beside the proof. If that request is still pending when proving
succeeds, the client cancels it and fetches again immediately. A completed request
is reused only if it succeeded and began at most ten seconds ago, including RPC
response latency. A proof error returns immediately without waiting for the
blockhash request. Merge submissions use the same rule.
The ten-second limit controls prefetch reuse; blockhash expiration follows chain
state and the returned `last_valid_block_height`.

`Submission::with_prover(Arc<dyn Prover>)` proves one submission with a
prover of the caller's, such as one on the device; `with_prover` on either
client builds one that proves every submission that way. Either prover only
proves what the client hands it, so the client fetches the proof data itself
and nothing reaches a prover server.

A remote prover requires a caller-supplied URL and policy. The SDK pins who
signs each network's prover policy, so a client follows new prover releases
without an SDK release. It downloads the signed policy again whenever it
attests again, every `max_age_secs` of the policy, and never uses it once its
release or its freshness part expires:

```rust
let prover = ProverClient::new(prover_url)
    .with_signed_tee(SignedTeePolicy::for_network(TeeNetwork::Mainnet));
```

An application that reviews each release itself can instead load that
release's policy JSON with `TeePolicy::from_file_json` and pass it to
`with_tee`, or its own release signers to `SignedTeePolicy::new(url, PolicySigners::new(network, keys, threshold)?)`.

The SDK embeds no prover URLs. The same policy parameter works
with a direct prover URL, a unified Helius API URL or a proxy path. Remote calls
without a policy fail before HTTP. Only loopback development without a proxy
permits plaintext. The explicit `for_tree_batches()` mode permits public
nullifier-tree batch proofs in plaintext and refuses every other proof.

The [TEE deployment guide](../../prover/tee/README.md) records the reviewed
policies and measured-build provenance. An older SDK can use a new deployment
policy when its schema, attestation protocol and circuits remain supported.
Image rebuilds and key rotations alone do not require an SDK release.

For readiness through the Helius API, use attestation and proving-key checks.
`check_indexed` and `check_setup(IndexerRequirement::Required)` also call the
operator `/health` route, which is not part of the public gateway API.

## Merging

A merge turns up to 52 plain UTXOs of one asset on one tree into one. The
owner enables it once by selecting the merge encryption scheme with
`set_merge_encryption_instruction(owner, MergeEncryptionScheme::PoseidonCtrV1)`,
which the owner signs; after that a merge with that scheme needs no owner
signature.

```rust
let inputs = select_merge(spendable.utxos(), asset, MERGE_DEFAULT_INPUT_COUNT, &reserved)?;
let tree_id = inputs[0].tree_id();
let merge = MergeTransaction::new(inputs)?
    .with_output_tree_id(tree_id)
    .with_expiry(now + 600)
    .encrypt(&keys)?;
let submission = MergeSubmission::new(&merge, owner, &address, &nullifier_key);
let signature = submission.send_sync(&client, &fee_payer)?;
```

`with_output_tree_id` is required in practice: without it the merged UTXO is
appended to tree 0. Pass the inputs' tree, or the tree the indexer names for
new outputs when that one is full or paused.

`prove_sync` checks the owner's record (PoseidonCtrV1 selected, same keys), fetches
the witness, proves and verifies the proof. The proof binds no fee payer, so
the `ProvedMerge` it returns is for any payer: `proved.instruction(payer)` is
the `merge_transact` to put in any message, for example a relayer's.
`finish_unsigned_sync(&client, fee_payer)` builds the message the payer signs
alone; `send_sync` signs, sends and waits as `Submission` does. As for
`Submission`, the generics and the blocking or async choice sit on these
methods, so `MergeSubmission` itself is a plain borrow. Set an expiry: until it passes,
anyone holding the proof can submit it. The proof request carries the
owner's nullifier secret, so a prover other than this process learns it and
every merged amount; `MergeSubmission::with_prover` keeps it in process.

## In process: litesvm

Any indexer serves a client. A blocking one answers the indexer half of
`Rpc` and implements `WitnessReader`, which has a default over `Rpc`:
`impl WitnessReader for MyIndexer {}`. `spr_program_test::SprProgramTest`
is one: `harness.into_client(ProverClient::local())
.with_proof_data_source(ProofDataSource::Client)` is a client whose RPC and
indexer are the litesvm harness, so a transfer proves, sends and confirms in
one process beside a prover server.

# Prover data source

`ProverClient` and `AsyncProverClient` use prover fetching by default.
Configure `PROVER_INDEXER_URL` and, when needed, `PROVER_INDEXER_API_KEY` on
the prover. The indexer must serve the same network. A prover without an
indexer refuses indexed requests with `ClientError::ProverIndexerUnconfigured`.

Opt into client fetching with
`with_proof_data_source(ProofDataSource::Client)`. Every prover URL, including
the Helius API, submits to `/prove/<key>`, polls `/prove/<key>/status`, and
uses `/prove/<key>/indexed` for prover-fetched data. Prover fetching remains
the default for every host. The Helius deployment must activate these REST
routes, pools and TEE header forwarding; the SDK does not infer capabilities
from the hostname. The setting lives on
`ProverClient` and `AsyncProverClient`. The `SprClient` method sets it on
the prover client it holds; a prover given with `with_prover` is handed the
data by the client. Custom-ring proof environments read it from the prover
client they are given.
Both modes support cached spends and merge outputs. The forester selects
client fetching with `--client-proof-data`.

The cache and its selected slots are public, so a one-input spend that reads
one slot, publishes no UTXO root and withdraws publicly reveals which cached
output it spends. Use the cache for short-lived batch work such as merges that
feed dependent proofs.
When a spend needs unlinkability, wait for tree inclusion and select no cache
slot. See "Cache privacy" in `docs/spec.md`.

Prover fetching sends locally prepared inputs to `/prove/<key>/indexed`. The prover
resolves Merkle paths and root contexts. The SDK binds the returned roots to
its original public statement and verifies the proof before returning
transaction data. `IndexerRpcConfig.require_slot` sets the minimum indexer
context slot for `SprClient` transactions; `UtxoScan::with_indexer_config`
applies it to wallet discovery, so a spend another client just made is read.
Wallet discovery and chain account reads still use the SDK's configured services.

`UtxoScan` scans the assets in the supplied `AssetRegistry` by default and
reports other asset ids and mints as unknown. Opt into on-chain SPL asset
discovery when the wallet should hold every registered asset:

```rust
let scan = UtxoScan::new(&keys, &assets)
    .with_indexer_config(IndexerRpcConfig::at_slot(confirmed_slot))
    .with_asset_discovery()
    .fetch(&client)?;
assets = scan.asset_registry;
```

An unknown asset triggers one filtered `getProgramAccounts` read of the
pool's SPL registrations, validated by owner, layout and mint PDA. The lookup
requires the greater of `require_slot` and every transaction slot fetched so
far. A lagging Solana RPC fails the scan. Registry validation and merging use
indexed mint lookups, so loading registrations takes linear time.

The scan decrypts its already fetched transactions again and follows newly resolved
nullifiers without repeating tag queries. `fetch_spl_asset_registrations`
exposes the same validated lookup separately with an optional minimum context
slot. Reuse the returned registry to cache mappings across scans; the input
registry is unchanged, including
on failure. Outputs in assets still unresolved after discovery are skipped;
the scan continues following known assets' nullifiers and reports the remaining
ids and mints through `unknown_asset_ids` and `unknown_mints` in both `spendable`
and `history`. These fields indicate outputs omitted from the balances and
history; an unknown id is sender-provided and is not evidence of a valid asset
or balance. RPC failures and invalid or conflicting registrations still fail
the scan. Leave discovery disabled for an explicit asset allowlist.
Custom `Rpc` implementations must support
`get_program_accounts_filtered`, including its minimum context slot; discovery
never falls back to an unfiltered or stale program listing.

`IndexedTransferPreparation` selects confidential, ring, ring-authority or
anonymous EdDSA authorization. `IndexedMergePreparation` supports both merge rails and
cache outputs. Pass the prepared request to `prove_indexed`, which checks the
returned roots, verifies the proof and returns transaction data. A ring merge
returns `ProvenIndexedMerge::Ring`.

Transfer, merge and indexed ring policy requests prefer a proof in the HTTP
response. A capacity rejection can retry through the queue when Redis is
available. Indexed deposit audits use synchronous delivery. Forester batch
proofs use queued delivery.
