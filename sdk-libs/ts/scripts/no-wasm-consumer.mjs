import assert from "node:assert/strict";

// Remove the global before any SDK module is evaluated.
Reflect.deleteProperty(globalThis, "WebAssembly");
assert.equal(typeof globalThis.WebAssembly, "undefined");

const {
  SHIELDED_POOL_PROGRAM_ID,
  LocalShieldedKeys,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  buildDepositTransaction,
  createSprClient,
  loadPersistedWallet,
  serializeWallet,
  syncPersistedWallet,
  walletSnapshotCipher,
} = await import("@heliuslabs/spr");
const { getCompiledTransactionMessageDecoder } = await import("@solana/kit");

const slot = 123;
const blockhash = "1".repeat(32);
const methods = [];
const client = await createSprClient({
  solanaRpcUrl: "http://127.0.0.1:8899",
  async fetch(_input, init) {
    const { id, method } = JSON.parse(init.body);
    methods.push(method);
    let result;
    switch (method) {
      case "getLatestBlockhash":
        result = { context: { slot }, value: { blockhash, lastValidBlockHeight: 200 } };
        break;
      case "getShieldedTransactionsByTags":
      case "getEncryptedUtxosByTags":
        assert.equal(init.redirect, "error");
        result = { context: { slot, blockTime: 1_700_000_000 }, data: [], paginationToken: null };
        break;
      default:
        assert.fail(`Unexpected method: ${method}`);
    }
    return Response.json({ jsonrpc: "2.0", id, result });
  },
});

// The owner hash is pinned by test-vectors/key_derivation.json.
const seed = new Uint8Array(32);
seed[31] = 1;
const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
seed.fill(0);
try {
  const identity = keypair.shieldedAddress();
  const feePayer = identity.solanaAddress();
  const transaction = await buildDepositTransaction({
    client,
    feePayer,
    recipient: identity,
    amount: 42n,
  });
  const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  assert.equal(message.version, 1);
  assert.deepEqual(Object.keys(transaction.signatures), [feePayer]);
  assert.equal(message.numInstructions, 1);
  const [deposit] = message.instructionHeaders;
  const [payload] = message.instructionPayloads;
  assert.equal(message.staticAccounts[deposit.programAccountIndex], SHIELDED_POOL_PROGRAM_ID);
  assert.ok(
    Buffer.from(payload.instructionData).includes(
      Buffer.from("1095ab4e1b59e42e4be89f49210af7f42ed3d7d9c45065afcce69a9c5a877e36", "hex"),
    ),
    "deposit instruction must contain the Rust owner hash",
  );

  const wallet = new Wallet({ identity });
  const cipher = walletSnapshotCipher(keypair);
  let saved;
  const store = {
    async load() {
      return saved;
    },
    async save(snapshot) {
      assert.equal(saved, undefined, "save once per sync");
      saved = snapshot;
    },
  };
  const { snapshot } = await syncPersistedWallet({
    client,
    wallet,
    keys: LocalShieldedKeys.fromKeypair(keypair),
    cipher,
    store,
  });
  assert.ok(saved);
  assert.notEqual(saved, snapshot, "save the encrypted snapshot");
  const restored = await loadPersistedWallet({ store, cipher });
  assert.ok(restored);
  assert.equal(serializeWallet(restored), snapshot);
  const { transactions, proofless } = JSON.parse(snapshot).syncCheckpoints;
  assert.ok(transactions.length > 0);
  assert.ok(proofless.length > 0);
  for (const checkpoint of [...transactions, ...proofless]) {
    assert.equal(checkpoint.slot, String(slot));
  }
  assert.deepEqual(methods, [
    "getLatestBlockhash",
    "getShieldedTransactionsByTags",
    "getEncryptedUtxosByTags",
  ]);
} finally {
  keypair.destroy();
}

// Node without WebAssembly stands in for Hermes, so the in-app check runs in CI.
const { checkHermesDeposit } = await import("./hermes-consumer.mjs");
globalThis.HermesInternal = {};
try {
  await checkHermesDeposit();
} finally {
  Reflect.deleteProperty(globalThis, "HermesInternal");
}
