# Rust decryption client

`DecryptionClient::connect` verifies Gatekeeper’s session using a signed
release and independently trusted authority keys and PCRs. Load the pin
from the application’s trusted deployment configuration.

Use `resolve_recipient(client.rpc(), owner)` to take the recipient’s
registered shielded address or look up its service keys after a confirmed
registry miss.

Use `open(&owner_signer)` to obtain `ServiceKeys` for notes sent to the
service address. The keys implement `ShieldedKeys` for sync and
`ProofAuthority` for spending. The recipient signs the decrypt request
off-chain for each batch.

After registration, scan the service wallet and the registered wallet with
their own keys. To consolidate the balances, spend from the service wallet
to the registered address with a funded fee payer.

[Devnet test](../../sdk-tests/client/rust/README.md#devnet-decryption) ·
[Security specification](../../services/decryption-service/enclave/SPEC.md)
