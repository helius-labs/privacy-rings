# Nitro decryption invariants

Run `cargo test --locked -p spr-client --features client -p spr-prover-tee`.

| Invariant | Coverage |
| --- | --- |
| Both signed feeds authorize the replica. Rollover accepts a lagging mirror only for the primary's immediate predecessor. | [Release policy](nitro_policy.rs) |
| Installed trust pins one exact policy at its minimum sequence. A competing policy at that sequence or a successor that names a different digest fails before checkpoint storage. | [Release policy](nitro_policy.rs) |
| Both signed heads must agree with the saved checkpoint wherever they expose its revision or immediate successor. Storage checks those links while committing the new checkpoint. | [Checkpoint](nitro_policy.rs) |
| A checkpoint read that crosses a policy deadline cannot authorize an operation. | [Deadline](nitro_policy.rs) |
| A stalled checkpoint read cannot dispatch an attestation probe after the monotonic connection deadline. An unsigned lookup refreshes a superseded policy once, preserving the fresh result or revocation. A rollback stops the lookup. | [Wallet transport](nitro_transport.rs) |
| A stalled file lock returns a storage error for reads and writes. After the lock is released, the last committed revision is still readable and its successor can commit. | [Lock contention](nitro_policy.rs) |
| The wallet commits its policy before contacting a replica. Reopening and concurrent writes preserve revocation, sequence, custody floor and recovery-only mode. | [Checkpoint](nitro_policy.rs) |
| A running reader remembers an accepted revocation after its checkpoint file is lost or restored to an older copy. Older heads and cached sessions fail. The authenticated current policy can repair the file. | [Checkpoint](nitro_policy.rs) |
| A fresh Nitro boot binds discovery, both boot points and PCR0–4. | [Discovery binding](nitro_exchange.rs) and the AWS evidence verifier tests in `spr-prover-tee` |
| The owner signs the exact network, release, response key, ordered batch and deadline. The wallet bounds the deadline by the verified session. Changing the deadline invalidates the signature. The reply must come from that boot and bind this request and ciphertext. | [Proofs and owner message](nitro_exchange.rs) · [Transport](nitro_transport.rs) |
| Reusing a boot for a payment requires reading both signed heads. A recovery-only primary with an exact predecessor on the mirror advances the checkpoint and blocks payment lookup. | [Transport](nitro_transport.rs) |
| A Nitro payment submission binds every output to its attached owner's exact resolved keys. It resolves again after signing. A key change during signing or a changed or incomplete transaction from an external signer blocks the RPC broadcast. | [Output binding and submission](nitro_payment.rs) |
| Owner approval rechecks the checkpoint after waiting for the signer slot. The wallet stops waiting when the attested session expires. A stalled signer keeps its slot until it returns, and the async runtime can shut down while it is busy. | [Signer queue, deadline and shutdown](nitro_owner.rs) |
| Wrong response keys and altered frames fail authentication. The wire format matches the service SDK. | [Envelope vectors](nitro_envelope.rs) |
| A registry miss can use service keys only on the service’s Solana network. Both async and blocking lookup reject a devnet service on a mainnet RPC. | [Wallet transport](nitro_transport.rs) |
| A retryable exchange failure discards the failed cached boot even on the last attempt. A rate-limited exchange returns HTTP 429 and preserves the boot. | [Exchange cache](nitro_transport.rs) |
| The wallet can look up keys and recover a note through the encrypted endpoint. It refuses another viewing key, an oversized item and a reply to a request revoked in flight. | [Wallet transport](nitro_transport.rs) |
| Owner-authorized decrypt reads both published heads before prompting, after signing and before opening the authenticated reply. A cached boot cannot receive an approval after a revocation the wallet sees at those checks. The same approval deadline bounds publisher reads and the replica response. | [Wallet transport](nitro_transport.rs) |

The wallet transport test uses a loopback peer and starts with a verified-session
fixture. The AWS evidence tests use measurements and evidence captured from an
AWS enclave. The signed policy and exchange vectors use synthetic keys and the
TypeScript service SDK.
