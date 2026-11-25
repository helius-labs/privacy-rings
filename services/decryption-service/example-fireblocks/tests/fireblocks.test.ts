import assert from "node:assert/strict";
import { test } from "node:test";

import {
  blockhash,
  compileTransaction,
  createSignableMessage,
  createTransactionMessage,
  generateKeyPairSigner,
  setTransactionMessageConfig,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";
import { fireblocksSigner } from "../fireblocks.js";

test("Fireblocks signs exact Ed25519 bytes and waits for the RAW result", async () => {
  const owner = await generateKeyPairSigner();
  const message = createSignableMessage(Uint8Array.of(0xff, 0x00, 0x12));
  const [expected] = await owner.signMessages([message]);
  const signature = expected?.[owner.address];
  assert.ok(signature);
  const fullSig = Buffer.from(signature).toString("hex");
  let polls = 0;
  const signer = fireblocksSigner({
    async createTransaction(input) {
      assert.deepEqual(input, {
        transactionRequest: {
          operation: "RAW",
          assetId: "SOL_TEST",
          source: { type: "VAULT_ACCOUNT", id: "7" },
          extraParameters: { rawMessageData: { messages: [{ content: "ff0012" }] } },
        },
      });
      return { data: { id: "request-1" } };
    },
    async getTransaction(input) {
      assert.deepEqual(input, { txId: "request-1" });
      polls++;
      return { data: polls === 1
        ? { status: "PENDING_SIGNATURE" }
        : { status: "COMPLETED", signedMessages: [{ signature: { fullSig } }] } };
    },
  }, "7", owner.address);

  assert.deepEqual(await signer.signMessages([message]), [expected]);
  assert.equal(polls, 2);
});

test("Fireblocks signs the original v1 message without a transaction parser", async () => {
  const owner = await generateKeyPairSigner();
  const message = setTransactionMessageFeePayer(owner.address, createTransactionMessage({ version: 1 }));
  const configured = setTransactionMessageConfig({ computeUnitLimit: 200_000, loadedAccountsDataSizeLimit: 100_000 }, message);
  const transaction = compileTransaction(setTransactionMessageLifetimeUsingBlockhash({
    blockhash: blockhash("11111111111111111111111111111111"),
    lastValidBlockHeight: 1n,
  }, configured));
  const [expected] = await owner.signTransactions([transaction]);
  const signature = expected?.[owner.address];
  assert.ok(signature);
  const fullSig = Buffer.from(signature).toString("hex");
  const signer = fireblocksSigner({
    async createTransaction({ transactionRequest }) {
      assert.equal(transactionRequest?.operation, "RAW");
      assert.deepEqual(transactionRequest.extraParameters, {
        rawMessageData: { messages: [{ content: Buffer.from(transaction.messageBytes).toString("hex") }] },
      });
      return { data: { id: "v1" } };
    },
    async getTransaction() {
      return { data: { status: "COMPLETED", signedMessages: [{ signature: { fullSig } }] } };
    },
  }, "7", owner.address);
  assert.deepEqual(await signer.signTransactions([transaction]), [expected]);
});

test("the Fireblocks adapter refuses another account's signature", async () => {
  const owner = await generateKeyPairSigner();
  const other = await generateKeyPairSigner();
  const message = createSignableMessage("approval");
  const [signed] = await other.signMessages([message]);
  const signature = signed?.[other.address];
  assert.ok(signature);
  const fullSig = Buffer.from(signature).toString("hex");
  const signer = fireblocksSigner({
    async createTransaction() { return { data: { id: "wrong-owner" } }; },
    async getTransaction() {
      return { data: { status: "COMPLETED", signedMessages: [{ signature: { fullSig } }] } };
    },
  }, "7", owner.address);
  await assert.rejects(signer.signMessages([message]), /different message or account/);
});

for (const status of ["FAILED", "REJECTED", "CANCELLED", "BLOCKED"]) {
  test(`Fireblocks ${status} stops the signing request`, async () => {
    const owner = await generateKeyPairSigner();
    const signer = fireblocksSigner({
      async createTransaction() { return { data: { id: "refused" } }; },
      async getTransaction() { return { data: { status, subStatus: "BLOCKED_BY_POLICY" } }; },
    }, "7", owner.address);
    await assert.rejects(signer.signMessages([createSignableMessage("approval")]), new RegExp(`${status}: BLOCKED_BY_POLICY`));
  });
}

test("Fireblocks must return a complete 64-byte signature", async () => {
  const owner = await generateKeyPairSigner();
  const signer = fireblocksSigner({
    async createTransaction() { return { data: { id: "malformed" } }; },
    async getTransaction() {
      return { data: { status: "COMPLETED", signedMessages: [{ signature: { fullSig: "00" } }] } };
    },
  }, "7", owner.address);
  await assert.rejects(signer.signMessages([createSignableMessage("approval")]), /malformed Ed25519 signature/);
});
