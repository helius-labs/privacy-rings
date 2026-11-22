# Nitro decryption invariants

Run `cargo test -p spr-client --lib nitro_` and
`cargo test -p spr-prover-tee --lib`.

| Invariant | Coverage |
| --- | --- |
| Both signed feeds authorize the replica. Rollover accepts a lagging mirror only for the primary's immediate predecessor. | [Release policy](nitro_policy.rs) |
| Installed trust pins one exact policy at its minimum sequence. A competing policy at that sequence or a successor that names a different digest fails before checkpoint storage. | [Release policy](nitro_policy.rs) |
| Both signed heads must agree with the saved checkpoint wherever they expose its revision or immediate successor. Storage checks those links while committing the new checkpoint. | [Checkpoint](nitro_policy.rs) |
| A checkpoint read that crosses a policy deadline cannot authorize an operation. | [Deadline](nitro_policy.rs) |
| The wallet commits its policy before contacting a replica. Reopening and concurrent writes preserve revocation, sequence, custody floor and recovery-only mode. | [Checkpoint](nitro_policy.rs) |
| A fresh Nitro boot binds discovery, both boot points and PCR0–4. | [Discovery binding](nitro_exchange.rs) and the AWS evidence verifier tests in `spr-prover-tee` |
| The owner signs the exact network, release, response key and ordered batch. The reply must come from that boot and bind this request and ciphertext. | [Proofs and owner message](nitro_exchange.rs) |
| Wrong response keys and altered frames fail authentication. The wire format matches the service SDK. | [Envelope vectors](nitro_envelope.rs) |
| A registry miss can use service keys only on the service’s Solana network. Both async and blocking lookup reject a devnet service on a mainnet RPC. | [Wallet transport](nitro_transport.rs) |
| The wallet can look up keys and recover a note through the encrypted endpoint. It refuses another viewing key, an oversized item and a reply to a request revoked in flight. | [Wallet transport](nitro_transport.rs) |

The wallet transport test uses a loopback peer and starts with a verified-session
fixture. The AWS evidence tests use measurements and evidence captured from an
AWS enclave. The signed policy and exchange vectors use synthetic keys and the
TypeScript service SDK.
