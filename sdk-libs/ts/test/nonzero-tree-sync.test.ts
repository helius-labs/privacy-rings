import { signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { treeAddress } from "../src/interface/pda/index.js";
import { bytes32, EncryptionMode, ShieldedKeypair } from "../src/keypair/index.js";
import { wireDecoder } from "../src/interface/decode.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ConfidentialSplit,
  LocalShieldedKeys,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  Wallet,
  decryptTransactions,
  encryptSplit,
  deserializeWallet,
  serializeWallet,
  type IndexedShieldedTransaction,
  type SppProofInputs,
  type OutputContext,
} from "../src/transaction/index.js";
import {
  proofInputFromEntry,
  authorizePrivateTransaction,
} from "../src/wallet/private-transaction.js";
import { authorizedPrivateTransactionMaterial } from "../src/client/ports.js";
import { createTransfer, createSplit } from "../src/wallet/actions.js";
import { createMerge } from "../src/wallet/merge.js";
import { encodeMergeOutputData } from "../src/transaction/serialization/merge.js";

const TREE_ID = 7;
const TREE = treeAddress(TREE_ID);

function funded(owner: ShieldedKeypair, amounts: readonly bigint[], treeId: number): Wallet {
  const wallet = new Wallet({ identity: owner.shieldedAddress() });
  const key = owner.nullifierKey();
  try {
    const utxos = amounts.map((amount, index) => {
      const utxo = new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: bytes32(new Uint8Array(32).fill(index + 25)),
      });
      const hash = utxo.hash(owner.nullifierPublicKey(), treeId);
      return {
        utxo,
        outputContext: { hash, tree: treeAddress(treeId), treeId, leafIndex: BigInt(index) },
        nullifier: utxo.nullifier(hash, key),
        spent: false,
      };
    });
    wallet._replace({ ...wallet._state(), utxos });
    return wallet;
  } finally {
    key.destroy();
  }
}

function publication(prepared: SppProofInputs): IndexedShieldedTransaction {
  return {
    slot: 11n,
    txSignature: signature("1".repeat(64)),
    txViewingPublicKey: prepared.externalData.txViewingPublicKey,
    salt: prepared.externalData.salt,
    outputSlots: prepared.externalData.outputs.map((output, index) => {
      const viewTag = prepared.externalData.resolvedOwnerTags[index];
      if (viewTag === undefined) throw new Error("missing view tag");
      return {
        viewTag,
        payload: output.data ?? new Uint8Array(),
        outputContext: {
          hash: output.utxoHash,
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: BigInt(index + 20),
        },
      };
    }),
    messages: [],
    nullifiers: [prepared.firstNullifier()],
    proofless: false,
  };
}

const decoder = wireDecoder(() => new Error("invalid test snapshot"));
function snapshot(serialized: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(serialized);
  return decoder.record(parsed, "snapshot");
}
function firstContext(value: Record<string, unknown>): Record<string, unknown> {
  const entries = decoder.list(value["utxos"], "utxos");
  const entry = decoder.record(entries[0], "utxos[0]");
  return decoder.record(entry["outputContext"], "outputContext");
}

describe("per-output commitment tree ids", () => {
  it("builds later transfers and splits in the selected nonzero tree", async () => {
    const owner = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    try {
      for (const action of ["transfer", "split"]) {
        for (const inCircuitOwner of [false, true]) {
          const wallet = funded(owner, [42n], TREE_ID);
          const created =
            action === "transfer"
              ? await createTransfer({
                  wallet,
                  payer: owner.shieldedAddress().solanaAddress(),
                  asset: SOL_MINT,
                  amount: 20n,
                  recipient: recipient.shieldedAddress(),
                })
              : createSplit({
                  wallet,
                  payer: owner.shieldedAddress().solanaAddress(),
                  asset: SOL_MINT,
                  parts: 2,
                });
          try {
            const authorized = await authorizePrivateTransaction(
              created.transaction,
              wallet,
              keys,
              [],
              undefined,
              undefined,
              inCircuitOwner,
            );
            const material = authorizedPrivateTransactionMaterial(authorized);
            if (material === undefined) throw new Error("missing authorization");
            expect([material.tree, material.proofInputs.outputTreeId]).toEqual([TREE, TREE_ID]);
            expect(material.proofInputs.inputUtxos.every((input) => input.treeId === TREE_ID)).toBe(
              true,
            );
          } finally {
            const reservation = created.transaction._reservationId();
            if (reservation !== undefined) wallet._releaseReservation(reservation);
          }
        }
      }
    } finally {
      keys.destroy();
      recipient.destroy();
      owner.destroy();
    }
  });

  it("opens split bundles and independently recoverable merge outputs on their nonzero trees", async () => {
    const owner = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    try {
      const source = funded(owner, [42n], TREE_ID);
      const entry = source.utxos()[0];
      if (entry === undefined) throw new Error("missing input");
      const input = proofInputFromEntry(entry, owner.shieldedAddress());
      const split = new ConfidentialSplit({
        owner: owner.shieldedAddress(),
        input,
        asset: SOL_MINT,
        numOutputs: 2,
        perOutputAmount: 21n,
        payer: owner.shieldedAddress().solanaAddress(),
      })
        .withOutputTreeId(TREE_ID)
        .prepare();
      const tx = viewing.transactionViewingKey(split.firstNullifier);
      try {
        const encrypted = encryptSplit(tx, {
          viewingPublicKey: owner.viewingPublicKey(),
          viewTag: owner.shieldedAddress().confidentialViewTag(),
          bundle: split.bundlePlaintext(new AssetRegistry()),
        });
        const prepared = split.finalize({
          txViewingPublicKey: encrypted.txViewingPublicKey,
          salt: encrypted.salt,
          payload: encrypted.payload,
        });
        const restored = new Wallet({ identity: owner.shieldedAddress() });
        await decryptTransactions({
          wallet: restored,
          keys,
          transactions: [publication(prepared)],
        });
        expect(restored.balance(SOL_MINT).amount).toBe(42n);
        expect(
          restored
            .utxos()
            .filter((item) => item.utxo.amount > 0n)
            .map((item) => item.utxo.amount),
        ).toEqual([21n, 21n]);
        expect(restored.utxos().every((item) => item.outputContext.treeId === TREE_ID)).toBe(true);
      } finally {
        tx.destroy();
      }

      const mergeSource = funded(owner, [20n, 30n], TREE_ID);
      const created = await createMerge({ wallet: mergeSource, keys, asset: SOL_MINT });
      try {
        expect([created.prepared.inputTreeId, created.prepared.outputTreeId]).toEqual([
          TREE_ID,
          TREE_ID,
        ]);
        const transaction: IndexedShieldedTransaction = {
          slot: 12n,
          txSignature: signature("1".repeat(64)),
          outputSlots: [
            {
              viewTag: owner.shieldedAddress().confidentialViewTag(),
              outputContext: {
                hash: created.prepared.outputHash(),
                tree: TREE,
                treeId: TREE_ID,
                leafIndex: 30n,
              },
              payload: encodeMergeOutputData({
                salt: created.prepared.outputCiphertextSalt(),
                ciphertext: created.prepared.outputCiphertext(),
              }),
            },
          ],
          messages: [],
          nullifiers: mergeSource.utxos().map((item) => item.nullifier),
          proofless: false,
        };
        const recovered = new Wallet({ identity: owner.shieldedAddress() });
        await decryptTransactions({ wallet: recovered, keys, transactions: [transaction] });
        expect([
          recovered.balance(SOL_MINT).amount,
          recovered.utxos()[0]?.outputContext.treeId,
        ]).toEqual([50n, TREE_ID]);
      } finally {
        mergeSource._releaseReservation(created.reservationId);
      }
    } finally {
      viewing.destroy();
      keys.destroy();
      owner.destroy();
    }
  });

  it("migrates canonical default-tree legacy snapshots and rejects missing or mismatched metadata", async () => {
    const owner = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    try {
      for (const version of [2, 3, 4, 5]) {
        const legacy = snapshot(serializeWallet(funded(owner, [42n], 0)));
        legacy["version"] = version;
        delete firstContext(legacy)["treeId"];
        const restored = deserializeWallet(JSON.stringify(legacy));
        expect(restored.utxos()[0]?.outputContext.treeId).toBe(0);
        expect(snapshot(serializeWallet(restored))["version"]).toBe(6);
        const supplied = snapshot(serializeWallet(funded(owner, [42n], TREE_ID)));
        supplied["version"] = version;
        expect(deserializeWallet(JSON.stringify(supplied)).utxos()[0]?.outputContext.treeId).toBe(
          TREE_ID,
        );
      }
      const missingDefault = snapshot(serializeWallet(funded(owner, [42n], 0)));
      delete firstContext(missingDefault)["treeId"];
      expect(() => deserializeWallet(JSON.stringify(missingDefault))).toThrow(
        "TRANSACTION_DESERIALIZE",
      );
      for (const version of [2, 3, 4, 5, 6]) {
        const missing = snapshot(serializeWallet(funded(owner, [42n], TREE_ID)));
        missing["version"] = version;
        delete firstContext(missing)["treeId"];
        expect(() => deserializeWallet(JSON.stringify(missing))).toThrow("TRANSACTION_DESERIALIZE");
      }
      for (const treeId of [0, 8, -1, 65536, "7", null]) {
        const malformed = snapshot(serializeWallet(funded(owner, [42n], TREE_ID)));
        firstContext(malformed)["treeId"] = treeId;
        expect(() => deserializeWallet(JSON.stringify(malformed))).toThrow(
          "TRANSACTION_DESERIALIZE",
        );
      }
      const wallet = funded(owner, [42n], 0);
      wallet._setSyncCheckpoint("transactions", "ab".repeat(32), 5n);
      const before = serializeWallet(wallet);
      const decrypt = vi.spyOn(keys, "decrypt");
      const derive = vi.spyOn(keys, "derive");
      const base = { hash: bytes32(new Uint8Array(32).fill(9)), tree: TREE, leafIndex: 40n };
      const malformed: readonly (readonly [OutputContext, string])[] = [
        [base, "TRANSACTION_MISSING_TREE_ID"],
        [{ ...base, treeId: 8 }, "TRANSACTION_OUTPUT_TREE_MISMATCH"],
        [{ ...base, treeId: -1 }, "TRANSACTION_INVALID_TREE_ID"],
      ];
      for (const [outputContext, code] of malformed) {
        await expect(
          decryptTransactions({
            wallet,
            keys,
            transactions: [
              {
                slot: 11n,
                txSignature: signature("1".repeat(64)),
                outputSlots: [
                  {
                    outputContext,
                    viewTag: owner.shieldedAddress().confidentialViewTag(),
                    payload: new Uint8Array(),
                  },
                ],
                messages: [],
                nullifiers: [],
                proofless: false,
              },
            ],
            config: { syncedAt: 100n },
          }),
        ).rejects.toMatchObject({ code });
        expect(serializeWallet(wallet)).toBe(before);
      }
      expect(decrypt).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
    } finally {
      keys.destroy();
      owner.destroy();
    }
  });

  for (const changeMode of [EncryptionMode.Hkdf, EncryptionMode.PoseidonKdf]) {
    it(`recovers mixed recipients and ${changeMode} sender change on a nonzero tree`, async () => {
      const sender = ShieldedKeypair.generate();
      const recipient = ShieldedKeypair.generate();
      const nullifierKey = sender.nullifierKey();
      const senderKeys = LocalShieldedKeys.fromKeypair(sender);
      const recipientKeys = LocalShieldedKeys.fromKeypair(recipient);
      try {
        const input = new Utxo({
          owner: sender.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: bytes32(new Uint8Array(32).fill(23)),
        });
        const inputHash = input.hash(sender.nullifierPublicKey(), TREE_ID);
        const nullifier = input.nullifier(inputHash, nullifierKey);
        const spend = new ProofInputUtxo({
          utxo: input,
          treeId: TREE_ID,
          nullifierPublicKey: sender.nullifierPublicKey(),
          nullifier,
        });
        const transfer = new ConfidentialTransfer(
          sender.shieldedAddress(),
          [spend],
          sender.shieldedAddress().solanaAddress(),
        )
          .withOutputTreeId(TREE_ID)
          .withChangeEncryptionMode(changeMode);
        transfer.sendSolWithMode(recipient.shieldedAddress(), 20n, EncryptionMode.Hkdf);
        transfer.sendSolWithMode(recipient.shieldedAddress(), 30n, EncryptionMode.PoseidonKdf);
        const prepared = transfer.sign(sender, new AssetRegistry());
        const transaction: IndexedShieldedTransaction = {
          slot: 10n,
          txSignature: signature("1".repeat(64)),
          txViewingPublicKey: prepared.externalData.txViewingPublicKey,
          salt: prepared.externalData.salt,
          outputSlots: prepared.externalData.outputs.map((output, index) => {
            const viewTag = prepared.externalData.resolvedOwnerTags[index];
            if (viewTag === undefined || output.data === undefined)
              throw new Error("missing output");
            return {
              viewTag,
              payload: output.data,
              outputContext: {
                hash: output.utxoHash,
                tree: TREE,
                treeId: TREE_ID,
                leafIndex: BigInt(index + 10),
              },
            };
          }),
          messages: [],
          nullifiers: [nullifier],
          proofless: false,
        };
        const recipientWallet = new Wallet({ identity: recipient.shieldedAddress() });
        const senderWallet = new Wallet({ identity: sender.shieldedAddress() });
        senderWallet._replace({
          ...senderWallet._state(),
          utxos: [
            {
              utxo: input,
              outputContext: { hash: inputHash, tree: TREE, treeId: TREE_ID, leafIndex: 5n },
              nullifier,
              spent: false,
            },
          ],
        });
        await decryptTransactions({
          wallet: recipientWallet,
          keys: recipientKeys,
          transactions: [transaction],
        });
        await decryptTransactions({
          wallet: senderWallet,
          keys: senderKeys,
          transactions: [transaction],
        });
        expect({
          recipient: recipientWallet.balance(SOL_MINT).amount,
          sender: senderWallet.balance(SOL_MINT).amount,
          recipientIds: recipientWallet.utxos().map((entry) => entry.outputContext.treeId),
          senderIds: senderWallet.utxos().map((entry) => entry.outputContext.treeId),
        }).toEqual({
          recipient: 50n,
          sender: 50n,
          recipientIds: [TREE_ID, TREE_ID],
          senderIds: [TREE_ID, TREE_ID],
        });
        expect(senderWallet.privateTransactions()).toEqual([
          expect.objectContaining({ kind: "privateTransfer", direction: "outbound", amount: 50n }),
        ]);
        const serialized = serializeWallet(recipientWallet);
        const snapshot: unknown = JSON.parse(serialized);
        expect(snapshot).toMatchObject({ version: 6 });
        const restored = deserializeWallet(serialized);
        expect(restored.utxos()).toEqual(recipientWallet.utxos());
        const first = restored.utxos()[0];
        if (first === undefined) throw new Error("missing restored output");
        const futureSpend = proofInputFromEntry(first, recipient.shieldedAddress());
        expect([futureSpend.treeId, futureSpend.hash()]).toEqual([
          TREE_ID,
          first.outputContext.hash,
        ]);
      } finally {
        senderKeys.destroy();
        recipientKeys.destroy();
        nullifierKey.destroy();
        sender.destroy();
        recipient.destroy();
      }
    });
  }
});
