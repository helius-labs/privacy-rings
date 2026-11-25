# Confidential transfer with Fireblocks

The example uses a Fireblocks vault's Solana account to sign transactions and
decrypt approvals. It deposits SOL, sends to the address's service keys,
claims the note, then sweeps it into the account's locally derived shielded
wallet. The on-chain transfer publishes the recipient's Solana owner tag.
The code verifies the recipient and the decryption service before depositing.

## Devnet

Run this example against a deployed enclave with a matching signed SDK release pin.

1. Create or select a funded Fireblocks Solana devnet vault account with no SPR
   registry record. Enable raw signing and allow it in the workspace policy.
2. Copy [`client.env.example`](client.env.example) to `.env` in this directory.
   Fill in the wallet's Fireblocks credentials and the decryption app's
   separate Boot Proof credentials. Set `EXAMPLE_ACCEPT_PUBLIC_RECIPIENT=1`
   to acknowledge that the owner tag will be public.
3. Set `API_KEY` for Helius RPC, indexer, and prover endpoints, or supply
   all three `ZOLANA_*` URLs.

Run from `services/decryption-service`.

```sh
just setup build-ts
npx --yes pnpm@9.15.0 --filter spr-fireblocks-typescript-client-example example
```

The signer uses Fireblocks raw Ed25519 signing for off-chain approvals and
the SDK's exact v1 transaction message bytes. It verifies
each signature against the expected account and bytes. The derivation
signature used for the local shielded wallet is key material.

Before any deposit, the example signs the derivation message twice and refuses
different signatures. This checks repeatability within this run; it does not
prove that Fireblocks returns the same signature across sessions. Confirm that
guarantee before reusing the derived shielded wallet. Otherwise, the first
derivation signature must be stored as secret key material; this example does
not store it. Turnkey still supplies the decryption service's Boot Proof.

## Localnet

`bash tests/localnet.sh 200 npx --yes pnpm@9.15.0 --filter spr-fireblocks-typescript-client-example example`
runs this copy with local Solana signers and the
loopback decryption testkit. It uses the validator, indexer, prover, and programs from
this checkout. [Localnet CI](../../../.github/workflows/decryption-service-localnet.yml)
`bash tests/with-local-decryption.sh npx --yes pnpm@9.15.0 --filter spr-fireblocks-typescript-client-example test`
exercises signed decrypt batches and commitment checks without a Solana
validator. These tests simulate Fireblocks responses; they do not contact
a Fireblocks workspace.
