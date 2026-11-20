# @heliuslabs/spr-decryption-service

Connect through Gatekeeper with the API key and signed pin for its deployment.

```ts
import { createGatekeeperDecryptionService } from "@heliuslabs/spr-decryption-service";
import { Wallet, buildTransferTransaction } from "@heliuslabs/spr";

// The sender uses the registry first and the service when the record is absent.
const service = createGatekeeperDecryptionService({
  network: "devnet",
  endpoint: new URL("https://devnet.helius-rpc.com"),
  apiKey,
});

const transfer = await buildTransferTransaction({
  client: spr,
  wallet: senderWallet,
  keys: senderKeys,
  feePayer: sender,
  recipient: recipientAddress,
  amount,
  decryptionService: service,
});

// The recipient supplies a Solana Kit MessagePartialSigner.
const keys = await service.open(owner, spr.proofService);
const received = new Wallet({ identity: keys.address() });
```

The transfer publishes the
recipient's Solana address as its owner tag. `open` signs an empty batch to
obtain the nullifier secret and returns SPR `WalletKeys`. Sync with those keys
to sign and decrypt note batches. Call `keys.destroy()` when finished. After registration, sync the earlier
service notes using the service wallet and its keys.

Gatekeeper bundles the Turnkey Boot Proof with each reply. The client verifies
the release, replica, and reply before opening it. Use `createDecryptionService`
with a Boot Proof resolver for a direct enclave endpoint. The supplied prover receives the spend
witness. Mainnet uses the SDK's [independent trust anchors](trust/mainnet.json)
and system clock, including when a caller supplies a fresh signed policy.

[Direct Turnkey example](../example) · [Security flow](../enclave/SPEC.md)
