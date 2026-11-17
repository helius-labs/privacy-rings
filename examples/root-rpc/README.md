# Root JSON-RPC prototype

All public indexer, encrypted prover, private-wallet and decryption calls can use
`POST /`. Routing metadata stays visible; witnesses and wallet operations stay
end-to-end encrypted. This is an opt-in experiment for the companion gateway
feature `spr-root-rpc-prototype`, not a deployed endpoint or a published SDK API.

Companion gateway draft: [monorepo #22388](https://github.com/helius-labs/monorepo/pull/22388).

The feature is additive. Existing `/v1/spr/*`, `/v1/private-wallet/*` and
`/v1/decryption/*` requests keep their current behavior. Removing the adapter
restores existing transport without migrating wallet keys or stored state.

## Try with an existing client

The adapter uses the existing fetch injection point. Keep existing SDK service
URLs and policies; the adapter translates supported outgoing requests to `/`.
No SDK defaults, endpoint resolution, enclave image or attestation pins change.
Use a local/staging gateway built with the companion feature, not production.

```js
import { createRootRpcFetch } from "./transport.mjs";

const rootFetch = createRootRpcFetch({
  endpoint: "http://127.0.0.1:8080/",
  legacyOrigin: "https://devnet.helius-rpc.com/",
});

// Add `fetch: rootFetch` to the existing SprClient configuration.
// For spr-tvc, use { fetch: rootFetch } as both the gateway transport and
// the prover transport. Keep the existing signed prover policy configured.
```

`legacyOrigin` limits interception to one origin. The request's API key is moved
to the root endpoint; conflicting keys are rejected. Policy downloads, Solana
RPC and unrelated services pass through. Unknown SPR paths, unbound query
parameters, plaintext proof submissions and encrypted queue polls fail locally.
There is no automatic retry or REST fallback. Signals, HTTP admission failures,
key-rotation codes, encrypted answers, Boot Proofs and replay headers survive.
The gateway must have its existing forwarding policies for `spr-tee`,
`spr-tee-enc`, `retry-after` and `idempotent-replayed` configured.

## Wire contract

The prototype reuses existing method identities and names so authorization,
rate-limit groups and billing ordinals do not change. Naming aliases can be
reviewed separately before promoting the API.

| Method                                                                   | Params                                                                                 | Result                                       |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------- |
| Existing public indexer method                                           | Existing params                                                                        | Existing indexer result                      |
| `zolanaProve`                                                            | `provingKey`, optional `indexed`, `encryptedRequest: {version: "v1", enc, ciphertext}` | `{version: "v1", ciphertext}`                |
| `zolanaProveStatus`                                                      | `provingKey`, `jobId`                                                                  | Existing queue status JSON, where supported  |
| `sprProverAttestation`                                                   | `nonce` (32 bytes, lowercase hex)                                                      | Existing attestation JSON                    |
| `sprProvingKeys`                                                         | `{}`                                                                                   | Existing proving-key catalog                 |
| `privateWalletSession`, `privateWalletEnroll`, `privateWalletOperations` | Existing corresponding gateway body                                                    | Existing gateway JSON, including Boot Proofs |
| `decryptionSession`, `decryptionOperations`                              | Existing corresponding gateway body                                                    | Existing gateway JSON, including Boot Proofs |

`enc` is a 32-byte HPKE encapsulation in lowercase hex. Ciphertext is hex encoded
only for JSON transport. It is decoded back to the identical bytes at the gateway.
For example:

```json
{
  "jsonrpc": "2.0",
  "id": "example",
  "method": "zolanaProve",
  "params": {
    "provingKey": "transfer_confidential_2_2",
    "encryptedRequest": {
      "version": "v1",
      "enc": "<64 lowercase hex characters>",
      "ciphertext": "<encrypted witness as lowercase hex>"
    }
  }
}
```

The client/enclave continues authenticating `POST /prove/<key>` (or `/indexed`)
with the existing v1 associated-data rules. The gateway maps this typed operation
to `/v1/spr/prove/<key>`. Substituting the key or indexed mode changes the
cryptographic target and fails authentication. Arbitrary paths, headers, hosts
and query strings are not accepted as routing params. Wallet calls still reach
the same canonical gateway handlers and replay namespace, where grants and
ownership checks run unchanged.

The JSON-RPC ID is a correlation ID; it is not an enclave authorization claim.
Prover failures that carry a valid encrypted response remain encrypted `result`
values: their authenticated inner status is authoritative. Unencrypted upstream
refusals become error `-32050`, with `data: {status, body, retryAfter}`. Invalid
facade params produce `-32602`. HTTP authentication/admission failures remain
HTTP failures. The adapter reconstructs the old transport response so existing
SDK decoders and verification remain in charge.

## Specification and checks

[openapi.json](openapi.json) describes one root POST operation, with alternatives
for each method and a batch schema. Indexer request schemas reference the existing
generated Rings specification; domain payload validation stays in the existing
services. Legacy aliases remain documented in the existing service specs.

```sh
node examples/root-rpc/generate-openapi.mjs
node --test examples/root-rpc/transport.test.mjs
```

The tests use the existing Go/Rust/TS encrypted prover vector and decrypt its
response with the expected response key. They also verify wallet envelopes,
key rotation, credential handling, cancellation and fail-closed routing.

## Limits before promotion

The gateway's existing root JSON-RPC request cap is 3 MiB, including hex expansion;
the adapter enforces that cap and bounds response reads to 12 MiB. Large legacy
proofs/indexer requests may exceed the root limit. This prototype does not raise
shared limits or silently fall back. Queue status is exposed for existing queue
backends; encrypted TEE queue submission/polling is not introduced. Binary proving
key downloads remain at their existing download URLs.

Gateway method/service-table entries must be present for every exposed operation.
Decryption depends on the companion gateway's existing decryption-routing PR.
Production billing/admission, browser/CORS behavior, full live wallet enrollment
and transfer E2E, large payload sizing, and a chosen final method/error taxonomy
must be qualified before enabling this in a production build. Mobile clients
remain unchanged, including their URL-bound prepared-transaction recovery domain.
