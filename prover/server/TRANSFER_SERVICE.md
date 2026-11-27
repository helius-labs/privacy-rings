# Transfer service

## Proof paths

A proof is sent to the path of the proving key that proves it,
`POST /prove/<key>` or `POST /prove/<key>/indexed`, and a queued proof is
polled at `GET /prove/<key>/status?jobId=<id>`, where `<key>` is the key file
name without `.key`: `transfer_confidential_2_2`, `merge_52_1`,
`batch_address-append_40_4999`. Every path is also served under `/v1/spr`.
A gateway routes and prices on the path alone, so it can send each key to a
pool of provers sized for it at a price that matches its cost, and send each
poll to the pool whose queue holds the job.

`--serve` (or `PROVER_SERVE_KEYS`) limits the keys a deployment proves, as
patterns over key names such as `transfer_*` or `*_54_*`; the default is
every key. A key the deployment does not serve answers `404` with code
`proving_key_not_served`, and a body that resolves to another key than its
path names answers `400` with code `proving_key_mismatch`. `/health` lists the
served keys.

## Proving-key downloads

`GET /proving-keys` (also `/v1/spr/proving-keys`) returns `keys`, each with
`name` and `artifacts`. Every artifact has `format` (`gnark` or `zopro`),
`sha256`, `size` in bytes, and a complete `url`. Each key has one gnark
artifact and, when published, a zopro conversion.

Clients compare the gnark checksum with their verifying-key pin. Downloaders
verify the chosen artifact's bytes against its own checksum. The catalog
lists manifest keys, independently of the deployment's enabled proof routes.

`runtime` holds the `abi`, the shielded-pool `programId` and the verifying key
of each confidential signer and merge circuit (`verifyingKeys`, keyed by key
name, each naming its gnark `provingKeySha256`). Clients that fetch the catalog
over an attested, encrypted session use it to prove and verify with these keys
instead of their compiled ones. `provingkeys/runtime-keys.json` embeds it in
the image; `cargo run -q -p xtask -- runtime-proving-keys` writes it from the protocol's
verifying keys, and the build refuses it unless every key matches the lockfile.

`provingkeys/zopro-keys.lock`, copied from the mobile SDK's native package,
pins each conversion to its gnark source checksum. Update it when source keys
change. Each manifest keeps its own download prefix; standard URLs use
`ZOLANA_PROVING_KEYS_URL`, and extension keys use their registered release URL.

This replaces `expectedSha256`, `loadedSha256`, `available`, and the response's
`prefix`. Upgrade server and clients together.

## Delivery

Transfers and merges return their proofs in the HTTP response by default.
Forester and custom proofs use the queue when Redis is configured.
`X-Async: true` selects queued delivery, including after a synchronous request
receives `429`. Queue fallback requires Redis.

`PROVER_TRANSFER_CONCURRENCY` bounds direct and queued transfers together
within one process. Its default is one. Forester memory settings do not
determine transfer capacity.

Waiting HTTP requests, indexer resolution included, are bounded at four
times the transfer capacity.
A disconnected request retains its execution slot until proving stops.
Increase capacity only after measuring throughput and latency together.
Each additional service process has its own capacity limit.

## Indexer data

Set `PROVER_INDEXER_URL` to enable `POST /prove/<key>/indexed`. Without it the
route answers `404` with code `indexer_unconfigured`, and `/health` reports
`indexed: false`. The service sends
JSON-RPC requests to that configured URL only. `PROVER_INDEXER_API_KEY` sets
its `api-key` query parameter. `PROVER_INDEXER_CONCURRENCY` bounds preparation requests.
Both delivery paths resolve proofs before acquiring a transfer execution slot.
Queued indexed jobs wait in their own Redis lists, read only by workers
with `PROVER_INDEXER_URL`.

Prover fetching is the SDK default. Select `proofDataSource: "client"` in
TypeScript or `with_proof_data_source(ProofDataSource::Client)` in Rust to
fetch proof data in the SDK. The forester uses `--client-proof-data` for the
same choice. Reuse the client between requests. Keep the prover and indexer
in the same availability zone and use the private indexer endpoint to avoid
another remote round trip.

The request contains `circuitType`, `prepared`, `trees`, `inputs`,
`publicInputs`, and optional `minContextSlot`. `prepared` uses the selected
circuit's JSON fields with paths, tree slots, and public input hash omitted.
Each tree has its base58 address and raw `id`. Each input has its `treeSlot`
and base58 `commitment`, or `null` for a dummy or cached input. `publicInputs`
contains the public transcript fields in circuit order, with the tree slot commitment
omitted. Fields use hex encoding. The resolver inserts that commitment at
position two before hashing the transcript.

State and nullifier requests run concurrently. Real and dummy nullifiers
share one request per tree. The resolver checks leaf, path, root, tree, and
root history position before proving. `minContextSlot` rejects older indexer
responses. Each transfer or merge input tree must start with a non-dummy
input. When all non-dummy inputs in a tree are cached, the resolver skips its
state path request and uses the cache root sentinel.

An output owner without a matching registry key fails with `422` and code
`registry_member_missing`, which names the member. Each built-in indexed
preparation failure has a stable `code`; queued jobs retain that same code
and diagnostic `detail` in their status. Responses remain encrypted on TEE
deployments. Upstream response text and request values are not copied into
these diagnostics.

| Failure | HTTP status | Code |
| --- | --- | --- |
| Requested output leaf is absent from the requested tree | 422 | `indexer_rpc_output_leaf_not_found` |
| Photon rejects request validation or a public key | 422 | `indexer_rpc_validation_error` / `indexer_rpc_invalid_pubkey` |
| Photon is behind, has not reached the requested context slot, or has an expired root | 503 + `Retry-After` | `indexer_rpc_stale_slot` / `indexer_rpc_minimum_context_slot` / `indexer_rpc_stale_root` |
| Photon reports a database or internal failure | 502 | `indexer_rpc_database_error` / `indexer_rpc_unexpected_error` |
| Upstream HTTP error | 502 | `indexer_http_<status>` |
| Transport failure / timeout / cancellation | 502 | `indexer_request_failed` / `indexer_request_timeout` / `indexer_request_canceled` |
| Invalid JSON / version / response ID | 502 | `indexer_response_json_invalid` / `indexer_response_version_mismatch` / `indexer_response_id_mismatch` |
| Missing or null RPC result | 502 | `indexer_response_result_missing` / `indexer_response_result_null` |
| Proof count / state binding / nullifier binding / root mismatch | 502 | `indexer_proof_count_mismatch` / `indexer_state_proof_binding_mismatch` / `indexer_nullifier_proof_binding_mismatch` / `indexer_proof_root_mismatch` |

These HTTP statuses describe synchronous requests. Queued submission still
returns `202`; a failed job's poll carries its reason in the response body.

Other validation and batch preparation failures use the named `indexer_*`
codes defined at their check sites. Local indexer lag and batch replay waits
have distinct retryable `indexer_*` reasons and preserve the not-ready
classification. An expired synchronous request still returns `408 proof_timeout`.

Photon supplies its structured reason as JSON-RPC `error.data.code`, preserving
its existing numeric RPC codes and messages. The prover accepts only known
reason/number pairs; missing, unknown, or inconsistent metadata stays `502`
with code `indexer_rpc_<number>`. RPC failures include `detail.method` and
`detail.rpcCode`; HTTP failures include `detail.method`. Deploy Photon with
the structured reasons before expecting the prover to distinguish missing
inputs from other errors sharing `-32600`. An absent leaf means the indexer
does not have that input in that tree; it does not establish whether a pending
transaction will create it later.

Upstream failure logs carry the same `code` and safe `detail`, alongside
`Indexer proof data unavailable`. Unknown extension failures use
`indexer_unexpected_error` and keep their underlying cause in server logs.

The returned proof includes `resolution` with the resolved trees, their roots
and history positions, and `publicInputHash`. The caller must bind those trees
to its request and recompute that hash from its intended public transcript
before it builds the transaction. Queued delivery preserves the same fields.
Only concurrent requests share an indexed job. New requests do not reuse a
completed indexed proof because its roots can have expired.

## Release and readiness

Build with `sh build-release.sh`. The release script rejects `GOFLAGS` and
uses Go compiler optimization and cryptographic assembly. The Just binary
recipes and release xtask use the same script. Docker invokes
that script and enables `--require-optimized-build`, which rejects debug
compiler flags, race instrumentation, and `purego` or `noasm` builds.
`GOAMD64=v1` is portable. Select `v3` only for a fleet that supports it.
`PROVER_PGO` can name a representative Go CPU profile at build time.
Published images take these settings from `release-build.env`. Commit a
selected profile and its metadata with the settings change. Local build
and compose overrides are available for experiments. See the
[GPU deployment guide](../../tools/gpu/README.md) for Vast and EC2.

Use `/health` for liveness and `/ready` for load balancer readiness.
`/ready` returns `503` with code `prover_not_ready` and `Retry-After` until
configured preloads succeed. Proof requests return the same response during
preload. With `--preload-keys none`, keys load
on demand and readiness does not guarantee a warm proof unless explicit
preload circuits are set. `--preload-circuits transfer-confidential:2:2`
selects one shape. A circuit name without a shape loads its supported shapes.
`rpc` and `local-rpc` preload all transfer and merge shapes. The compose default preloads selected transfer 2×2 shapes and merge 24×1.
Provision memory for the selected keys and workers. The `Dockerfile.light`
prover fetches keys into `/proving-keys` on first use. An image built with
`PROVER_EXTENSION_REF` also bakes the extension release keys there, and a volume mounted
at `/proving-keys` replaces them, so the volume must hold them too.

## Capacity and monitoring

`compose.transfer.yml` builds the current source with two shared transfer
workers, Redis fallback, and a local Prometheus. Start it with
`docker compose -f compose.transfer.yml up --build`. The indexer setting
remains optional. Restrict access and set `PROVER_API_KEY` before exposing
the prover outside the local machine.

Scrape `/metrics` on the metrics port. Transfer capacity and active permits
cover direct and queued execution together. Completion counters cover both
delivery modes. HTTP duration includes indexer preparation and admission.
Its `status` label is `unavailable` for a `503` with `Retry-After` and
`upstream` for `502`, so the `5xx` failure alert counts neither.
A queued `202` measures acceptance only. Use queue delay and generation
duration to assess queued work. Network RTT and client polling need client
measurements.

Set `PROVER_REQUEST_TIMING=true` and send `X-Prover-Timing: true` to inspect
synchronous request stages. `Server-Timing` reports durations in milliseconds.
The response `X-Prover-Timing` contains stage offsets from server receipt and
marks unfinished stages with `complete: false`. `X-Request-ID` correlates the
response with its timing log. Indexer RPC stages overlap within `indexer_fetch`.
The `server` response duration ends before the response body is written.

`prover_sync_admission_wait_seconds` separates permit waiting by `admitted`
and `rejected` outcome. `prover_system_memory_bytes` is sampled during each
metrics scrape. The per-proof `prover_proof_memory_usage_bytes` and
`prover_proof_peak_memory_bytes` metrics are removed. Concurrent allocations
cannot be attributed to one proof. Use process memory gauges for capacity.

Load `monitoring/alerts.yml` into Prometheus. Set the throughput target and
latency thresholds to the deployment SLO. The example throughput target is
for the whole `prover` job. Queue depth is shared across replicas, so the
rules use the maximum depth rather than adding duplicate observations.
The throughput alert requires backlog and does not fire for idle service.
Configure an Alertmanager and notification receiver in your deployment to
send alerts. The compose profile exposes firing alerts in Prometheus.
Import `monitoring/dashboard.json` into Grafana and select the Prometheus
data source. Validate rules with `promtool check rules monitoring/alerts.yml`
and `promtool test rules monitoring/alerts.test.yml`.

On saturation, compare completion rate, queue depth, request latency, and
process memory. Increase `PROVER_TRANSFER_CONCURRENCY` one step and repeat
the load test. Add replicas when concurrency raises latency without enough
throughput gain. Gnark can use several CPU cores per proof, so worker count
must not be set equal to CPU count without measurement.
