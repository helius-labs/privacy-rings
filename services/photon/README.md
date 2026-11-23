# Photon: the Rings Indexer

Photon indexes Rings shielded-pool transactions and exposes the Rings JSON-RPC API:

- `getEncryptedUtxosByTags`
- `getShieldedTransactionsBySignature`
- `getShieldedTransactionsByTags`
- `getMerkleProofs`
- `getNonInclusionProofs`
- `getNullifierQueueElements`
- `getUserRecords`

Photon is built from the Zolana Cargo workspace so its event parser, tree
layout, SDK contract, and localnet tests always use the same source revision.

On method paths such as `/v1/spr/getUserRecords`, Photon accepts only a
single JSON-RPC call naming that method. Batches, duplicate method fields,
and path/body mismatches return HTTP 400 before execution, so a gateway can
route and price calls by URL. Root JSON-RPC and GET health checks stay available.

## Quick Start

Run against a local validator:

```bash
cargo run -p photon-indexer --bin photon
```

Run against a specific RPC URL:

```bash
cargo run -p photon-indexer --bin photon -- --rpc-url=http://127.0.0.1:8899
```

Use Postgres instead of the default temporary SQLite database:

```bash
export DATABASE_URL="postgres://postgres@localhost/postgres"
cargo run -p photon-indexer --bin photon-migration -- up
cargo run -p photon-indexer --bin photon -- --db-url="$DATABASE_URL"
```

Use Yellowstone gRPC for block streaming:

```bash
cargo run -p photon-indexer --bin photon -- \
  --rpc-url=https://api.devnet.solana.com \
  --grpc-url=<grpc_url>
```

## Rings BlockInfo Snapshots

Photon snapshots store filtered `BlockInfo` payloads, not materialized database rows. The
snapshotter keeps only transactions that contain Rings events, so a new Photon binary can replay
the snapshot through the current parser and persistence code even when the internal database schema
changes.

Write snapshots to a local directory:

```bash
cargo run -p photon-indexer --bin photon-snapshotter -- \
  --rpc-url=https://api.mainnet-beta.solana.com \
  --snapshot-dir=./rings-snapshots \
  --start-slot=<slot>
```

Serve existing snapshots without generating new ones:

```bash
cargo run -p photon-indexer --bin photon-snapshotter -- \
  --snapshot-dir=./rings-snapshots \
  --disable-snapshot-generation
```

Download snapshots from a snapshotter:

```bash
cargo run -p photon-indexer --bin photon-snapshot-loader -- \
  --snapshot-server-url=http://127.0.0.1:8825 \
  --snapshot-dir=./rings-snapshots
```

Bootstrap Photon from snapshots, then continue live indexing from the restored slot:

```bash
cargo run -p photon-indexer --bin photon -- \
  --db-url="$DATABASE_URL" \
  --rpc-url=https://api.mainnet-beta.solana.com \
  --snapshot-dir=./rings-snapshots
```

`--r2-bucket`/`--r2-prefix`, `--s3-bucket`/`--s3-prefix` and `--gcs-bucket`/`--gcs-prefix` are
available for remote snapshot storage. S3 takes its region from `AWS_REGION` and its credentials
from the environment, the `AWS_PROFILE` profile, or the ECS task or instance role. With
`AWS_ENDPOINT` set it talks to that S3-compatible store with path-style requests.

Snapshot read, decoding, or premature EOF errors fail startup with a nonzero exit status.
After correcting the source or connectivity, restart with the same snapshot options: committed
blocks remain in the database, and Photon verifies batches it has already applied before continuing.

## Operations

### Ring-scoped history

`getShieldedTransactionsByTags` and `getEncryptedUtxosByTags` accept `tags: []`
only with an explicit `ringProgramId`. The scan includes the ring's deposits,
transfers and merges without recipient tags. The filter uses the SPP instruction's
ring-config account, including rings whose registration was not indexed.
An empty tag list without a ring is rejected. Nonempty tags still narrow the scan.

Pages use gTFA-style pagination: pass `paginationToken` back with the
same filters until it is null. To resume after new indexing, read again with
`filters: { slot: { gt } }` set to the last page's `context.slot`. That slot is
covered only by a read without an `lt` or `lte` bound; a capped read covered the
slots below its cap.
Ciphertexts stay opaque to Photon. Auditor recovery decrypts the returned deposit
capsules and transfer messages client-side.

Photon fails closed when it cannot safely reconstruct Rings nullifier tree batches. A
non-contiguous nullifier queue or reconstructed-root mismatch makes the indexer retry the same
block batch until the underlying data or code is fixed. Alert on stale `getIndexerHealth` results,
`block_batch_index_failures`, and errors containing `Cannot reconstruct nullifier batch` or
`Reconstructed nullifier root mismatch`.

### Forwarding to upstreams

Photon can forward the JSON-RPC methods it does not serve to other services, so
clients keep one endpoint. Photon never forwards a method it serves, whatever an
upstream announces.

Roles:

- **Upstream.** A JSON-RPC service with an Ed25519 key. It posts
  `announceUpstream` to the registry on a timer, signed over its URL, its method
  names and a timestamp. `spr_rpc_http::announce::Announcer` does this.
- **Registry.** A Photon started with `--upstream-registry-bind <address>`. It
  records each announcement in `rpc_upstreams`, and a new key starts as pending.
  The address must be loopback or private, because any key may write a pending
  row.
- **Operator.** Approves an upstream with `photon-upstreams`, against the same
  database.
- **Forwarder.** Every Photon started with `--forward-upstreams`. It reads the
  approved rows every five seconds.

```bash
export DATABASE_URL=postgres://...
photon-upstreams list
photon-upstreams approve <pubkey> <url>
photon-upstreams revoke <pubkey>
```

What approval locks in:

- The URL. `approve` takes the URL the operator read and fails when the key has
  announced another one since. After the key announces a new URL, Photon
  keeps the approved URL until the operator approves the new one.
- Not the methods. The approved key adds and removes methods with its next
  announcement.
- Precedence. When two approved upstreams announce one method, the upstream
  approved first serves it.

Pitfalls:

- Photon passes `x-forwarded-for` through and does not add the peer address. A
  client can set that header, so an upstream may use it for rate limits only
  when a gateway in front of Photon overwrites it.
- Photon also passes `x-api-key` and the query string, so a gateway API key
  reaches the upstream.
- An announcement does not name a cluster. Run one registry database per
  cluster and approve each key there.
- Photon does not retry a forwarded call and does not follow a redirect. An
  upstream that does not answer gives HTTP 502 with JSON-RPC error `-32603`.
- A call passes through two forwarders at most. A third answers HTTP 508.

### Container releases

Images are published by `.github/workflows/publish-image.yml`, which publishes
photon, the prover and the forester, through the protected `image-publish`
environment. Configure `vars.AWS_IMAGE_PUBLISHER_ROLE_ARN` as a repository
variable holding an AWS IAM role that trusts GitHub's OIDC provider only for
`repo:helius-labs/zolana:environment:image-publish`, and restrict that role to
the zolnet ECR repositories.

Two channels. `release` requires the tag to name the commit
(`<service>-zolana-<12-character-zolana-commit>`) and the commit to be on `main`;
the imported crate's upstream version is not a Zolana release version. `preview`
takes any branch and any tag, and refuses a `-zolana-` tag so a preview cannot
claim a release name. Both are attested and immutable.

The registry is private ECR with `IMMUTABLE` tags, so the registry itself refuses
to move a published tag. The workflow also serializes publishes per service,
refuses tags that already exist, publishes the `sha-<commit>` alias first, and
verifies both remote tags resolve to the same digest — a clearer failure than a
push rejection, not the only guard.

## Development

Run the Rings integration tests:

```bash
cargo test -p photon-indexer
```

Check the main binary:

```bash
cargo check -p photon-indexer --bin photon
```

Generate the Rings OpenAPI spec:

```bash
npm install --global @apidevtools/swagger-cli@4.0.4
cargo run -p photon-indexer --bin photon-openapi
```
