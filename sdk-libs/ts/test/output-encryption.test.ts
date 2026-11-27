import { address, signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import fixture from "../../../test-vectors/output_encryption.json" with { type: "json" };
import {
  EncryptionMode,
  ShieldedAddress,
  ShieldedKeypair,
  ViewingKey,
  bytes16,
  bytes32,
} from "../src/keypair/index.js";
import { checkedEncryptionMode } from "../src/keypair/encryption-mode.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../src/interface/tree-slot.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  EncryptedScheme,
  LocalShieldedKeys,
  ProofInputUtxo,
  Mint,
  SOL_MINT,
  Wallet,
  Utxo,
  WithdrawalTarget,
  createProofOutput,
  decodeConfidential,
  decodeOutputData,
  decryptPoseidonKdf,
  decryptPoseidonKdfAsSender,
  decryptTransactions,
  encodeConfidentialSlots,
  type ConfidentialOutputPlaintext,
  type DecryptLabel,
  type IndexedShieldedTransaction,
  type ShieldedKeys,
} from "../src/transaction/index.js";
import {
  decryptConfidentialAsSender,
  encodeConfidential,
  encodeOutputData,
  encryptConfidential,
  encryptPoseidonKdf,
} from "../src/transaction/serialization/codecs.js";

function bytes(encoded: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/u.test(encoded)) throw new Error("invalid vector hex");
  return new Uint8Array(Buffer.from(encoded, "hex"));
}

function hex(encoded: Uint8Array): string {
  return Buffer.from(encoded).toString("hex");
}

describe("output encryption shared with Rust", () => {
  for (const vector of fixture.vectors) {
    it(vector.name, () => {
      const mode = checkedEncryptionMode(vector.mode);
      const tx = ViewingKey.fromBytes(bytes32(bytes(vector.tx_secret)));
      const recipient = ViewingKey.fromBytes(bytes32(bytes(vector.recipient_secret)));
      try {
        expect(fixture.version).toBe(1);
        expect([hex(tx.publicKey().toBytes()), hex(recipient.publicKey().toBytes())]).toEqual([
          vector.tx_pubkey,
          vector.recipient_pubkey,
        ]);
        const salt = bytes16(bytes(vector.salt));
        const plaintext: ConfidentialOutputPlaintext = {
          assetId: BigInt(vector.asset_id),
          amount: BigInt(vector.amount),
          blinding: bytes32(bytes(vector.blinding)),
          data: new Data([{ kind: "memo", bytes: bytes(vector.memo) }]),
        };
        const serialized = encodeConfidential(plaintext);
        expect(hex(serialized)).toBe(vector.plaintext);
        const ciphertext = tx.encryptSlotWithMode(
          recipient.publicKey(),
          serialized,
          salt,
          vector.slot_index,
          mode,
        );
        expect(hex(ciphertext)).toBe(vector.ciphertext);
        expect(
          recipient.decryptUtxoWithMode(ciphertext, tx.publicKey(), salt, vector.slot_index, mode),
        ).toEqual(serialized);
        const body =
          mode === EncryptionMode.PoseidonKdf
            ? encryptPoseidonKdf(tx, recipient.publicKey(), plaintext, salt, vector.slot_index)
            : encryptConfidential(tx, recipient.publicKey(), plaintext, salt, vector.slot_index);
        const scheme =
          mode === EncryptionMode.PoseidonKdf
            ? EncryptedScheme.poseidonKdf
            : EncryptedScheme.confidential;
        const frame = encodeOutputData(scheme, body);
        expect(hex(frame)).toBe(vector.frame);
        expect(decodeOutputData(frame)).toEqual({ encoding: "encrypted", scheme, body });
        const opened =
          mode === EncryptionMode.PoseidonKdf
            ? decryptPoseidonKdf(body, {
                viewingKey: recipient,
                txViewingPublicKey: tx.publicKey(),
                salt,
                slotIndex: vector.slot_index,
              })
            : decodeConfidential(
                recipient.decryptUtxo(body.subarray(33), tx.publicKey(), salt, vector.slot_index),
              );
        const senderOpened =
          mode === EncryptionMode.PoseidonKdf
            ? decryptPoseidonKdfAsSender(tx, body, salt, vector.slot_index)
            : decryptConfidentialAsSender(tx, body, salt, vector.slot_index);
        expect([opened, senderOpened]).toEqual([plaintext, plaintext]);
        if (mode === EncryptionMode.PoseidonKdf) {
          const changed = frame.slice();
          changed[0] = 2;
          expect(() => decodeOutputData(changed)).toThrow("TRANSACTION_BAD_DISCRIMINATOR");
        }
      } finally {
        tx.destroy();
        recipient.destroy();
      }
    });
  }

  it("rejects a single embedded-key mutation and retains the transaction error category", () => {
    const vector = fixture.vectors.find((entry) => entry.mode === "poseidonKdf");
    if (vector === undefined) throw new Error("missing Poseidon vector");
    const tx = ViewingKey.fromBytes(bytes32(bytes(vector.tx_secret)));
    const recipient = ViewingKey.fromBytes(bytes32(bytes(vector.recipient_secret)));
    const replacement = ViewingKey.fromBytes(bytes32(new Uint8Array(32).fill(11)));
    const { body } = decodeOutputData(bytes(vector.frame));
    const salt = bytes16(bytes(vector.salt));
    const cx = {
      viewingKey: recipient,
      txViewingPublicKey: tx.publicKey(),
      salt,
      slotIndex: vector.slot_index,
    };
    try {
      expect(decryptPoseidonKdf(body, cx).amount).toBe(BigInt(vector.amount));
      const changed = body.slice();
      changed.set(replacement.publicKey().toBytes());
      expect(changed.subarray(33)).toEqual(body.subarray(33));
      expect(() => decryptPoseidonKdf(changed, cx)).toThrow(
        "TRANSACTION_RECIPIENT_VIEWING_KEY_MISMATCH",
      );
      expect(() =>
        decryptPoseidonKdf(body, { viewingKey: recipient, slotIndex: vector.slot_index }),
      ).toThrow("TRANSACTION_MISSING_ENCRYPTION_CONTEXT");
      recipient.destroy();
      expect(() => decryptPoseidonKdf(body, cx)).toThrow("TRANSACTION_KEYPAIR");
    } finally {
      tx.destroy();
      recipient.destroy();
      replacement.destroy();
    }
  });

  it("keeps per-output mode out of hashes and rejects invalid explicit selection", () => {
    const recipient = ShieldedKeypair.generate();
    try {
      const output = createProofOutput({
        ownerAddress: recipient.shieldedAddress(),
        asset: SOL_MINT,
        mint: Mint.fromRegistry(new AssetRegistry(), SOL_MINT),
        amount: 42n,
        blinding: bytes32(new Uint8Array(32).fill(9)),
      });
      const poseidon = output
        .withEncryptionMode(EncryptionMode.PoseidonKdf)
        .withMemo(new Uint8Array([1]));
      expect([
        output.encryptionMode,
        poseidon.encryptionMode,
        poseidon.withEncryptionMode(EncryptionMode.Hkdf).encryptionMode,
      ]).toEqual([EncryptionMode.Hkdf, EncryptionMode.PoseidonKdf, EncryptionMode.Hkdf]);
      expect(poseidon.hash(DEFAULT_TREE_ID)).toEqual(output.hash(DEFAULT_TREE_ID));
      expect(() => Reflect.apply(output.withEncryptionMode, output, [undefined])).toThrow(
        "TRANSACTION_KEYPAIR",
      );
      expect(() => Reflect.apply(output.withEncryptionMode, output, ["other"])).toThrow(
        "TRANSACTION_KEYPAIR",
      );
    } finally {
      recipient.destroy();
    }
  });

  it("keeps recipient KDFs independent of generated change and freezes change after preparation", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const bob = ShieldedKeypair.generate();
    const nullifierKey = sender.nullifierKey();
    const keys = LocalShieldedKeys.fromKeypair(sender);
    try {
      const utxo = new Utxo({
        owner: sender.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding: bytes32(new Uint8Array(32).fill(12)),
      });
      const input = new ProofInputUtxo({
        utxo,
        nullifierPublicKey: sender.nullifierPublicKey(),
        nullifier: utxo.nullifier(
          utxo.hash(sender.nullifierPublicKey(), DEFAULT_TREE_ID),
          nullifierKey,
        ),
      });
      const build = (): ConfidentialTransfer =>
        new ConfidentialTransfer(
          sender.shieldedAddress(),
          [input],
          sender.shieldedAddress().solanaAddress(),
        );
      const normal = build();
      normal.send(recipient.shieldedAddress(), SOL_MINT, 42n);
      expect(normal.prepare().outputs.map((output) => output.encryptionMode)).toEqual([
        EncryptionMode.Hkdf,
        EncryptionMode.Hkdf,
      ]);

      for (const helper of ["asset", "sol"]) {
        const paymentAsset =
          helper === "asset" ? address("So11111111111111111111111111111111111111112") : SOL_MINT;
        const assets = new AssetRegistry();
        if (helper === "asset") assets.register(9n, paymentAsset);
        const paymentUtxo = new Utxo({
          owner: sender.signingPublicKey(),
          asset: paymentAsset,
          amount: 100n,
          blinding: bytes32(new Uint8Array(32).fill(13)),
        });
        const paymentInput = new ProofInputUtxo({
          utxo: paymentUtxo,
          nullifierPublicKey: sender.nullifierPublicKey(),
          nullifier: paymentUtxo.nullifier(
            paymentUtxo.hash(sender.nullifierPublicKey(), DEFAULT_TREE_ID),
            nullifierKey,
          ),
        });
        const perCall = new ConfidentialTransfer(
          sender.shieldedAddress(),
          [paymentInput],
          sender.shieldedAddress().solanaAddress(),
        ).withChangeEncryptionMode(EncryptionMode.PoseidonKdf);
        expect(() =>
          Reflect.apply(perCall.sendWithMode, perCall, [
            recipient.shieldedAddress(),
            paymentAsset,
            1n,
            undefined,
          ]),
        ).toThrow("TRANSACTION_KEYPAIR");
        if (helper === "asset") {
          perCall.sendWithMode(
            recipient.shieldedAddress(),
            paymentAsset,
            42n,
            EncryptionMode.PoseidonKdf,
          );
        } else {
          perCall.sendSolWithMode(recipient.shieldedAddress(), 42n, EncryptionMode.PoseidonKdf);
        }
        perCall.send(bob.shieldedAddress(), paymentAsset, 10n);
        const payments = perCall.sign(sender, assets);
        const real = payments.outputs.flatMap((output, index) => {
          if (output.isDummy()) return [];
          const encoded = payments.externalData.outputs[index];
          if (encoded?.data === undefined || output.ownerAddress === undefined)
            throw new Error("missing recipient ciphertext");
          return [
            {
              owner: output.ownerAddress.solanaAddress(),
              amount: output.amount,
              scheme: decodeOutputData(encoded.data).scheme,
            },
          ];
        });
        expect(real.map((entry) => [entry.amount, entry.scheme])).toEqual([
          [48n, 9],
          [42n, 9],
          [10n, 3],
        ]);
        expect(
          [recipient, bob, sender].map(
            (actor) =>
              real.find((entry) => entry.owner === actor.shieldedAddress().solanaAddress())?.scheme,
          ),
        ).toEqual([9, 3, 9]);
      }

      const transfer = build().withChangeEncryptionMode(EncryptionMode.PoseidonKdf);
      transfer.send(recipient.shieldedAddress(), SOL_MINT, 42n);
      const prepared = transfer.prepare();
      expect(prepared.outputs.map((output) => [output.amount, output.encryptionMode])).toEqual([
        [58n, EncryptionMode.PoseidonKdf],
        [42n, EncryptionMode.Hkdf],
      ]);
      expect(() => transfer.withChangeEncryptionMode(EncryptionMode.Hkdf)).toThrow(
        "TRANSACTION_OUTPUT_UTXOS_ALREADY_PADDED",
      );
      const signed = transfer.sign(sender, new AssetRegistry());
      const transaction: IndexedShieldedTransaction = {
        slot: 2n,
        txSignature: signature("1".repeat(64)),
        txViewingPublicKey: signed.externalData.txViewingPublicKey,
        salt: signed.externalData.salt,
        outputSlots: signed.externalData.outputs.map((output, index) => {
          const viewTag = signed.externalData.resolvedOwnerTags[index];
          if (viewTag === undefined || output.data === undefined)
            throw new Error("missing ciphertext");
          return {
            viewTag,
            payload: output.data,
            outputContext: {
              hash: output.utxoHash,
              tree: treeAddress(DEFAULT_TREE_ID),
              leafIndex: BigInt(index),
            },
          };
        }),
        messages: [],
        nullifiers: [input.nullifier()],
        proofless: false,
      };
      expect(transaction.outputSlots.map((slot) => decodeOutputData(slot.payload).scheme)).toEqual([
        EncryptedScheme.poseidonKdf,
        EncryptedScheme.confidential,
      ]);
      const wallet = new Wallet({ identity: sender.shieldedAddress() });
      await decryptTransactions({ wallet, keys, transactions: [transaction] });
      expect(wallet.balance(SOL_MINT).amount).toBe(58n);

      const fallback = build().withChangeEncryptionMode(EncryptionMode.PoseidonKdf);
      fallback.withdraw(
        SOL_MINT,
        100n,
        WithdrawalTarget.sol({ recipient: sender.shieldedAddress().solanaAddress() }),
      );
      const fallbackPrepared = fallback.prepare();
      expect(
        fallbackPrepared.outputs.map((output) => [output.amount, output.encryptionMode]),
      ).toEqual([[0n, EncryptionMode.PoseidonKdf]]);
      const fallbackDummies = fallbackPrepared.proofOutputs().filter((output) => output.isDummy());
      expect(fallbackDummies.length).toBeGreaterThan(0);
      expect(fallbackDummies.every((output) => output.encryptionMode === EncryptionMode.Hkdf)).toBe(
        true,
      );

      const failed = build();
      failed.send(recipient.shieldedAddress(), SOL_MINT, 101n);
      expect(() => failed.prepare()).toThrow("TRANSACTION_INSUFFICIENT_BALANCE");
      expect(failed.withChangeEncryptionMode(EncryptionMode.PoseidonKdf)).toBe(failed);
    } finally {
      keys.destroy();
      nullifierKey.destroy();
      sender.destroy();
      recipient.destroy();
      bob.destroy();
    }
  });

  for (const modes of [
    [EncryptionMode.Hkdf, EncryptionMode.PoseidonKdf, EncryptionMode.Hkdf],
    [EncryptionMode.PoseidonKdf, EncryptionMode.Hkdf, EncryptionMode.PoseidonKdf],
  ]) {
    it(`syncs mixed modes in physical order ${modes.join(",")} with a retired recipient key`, async () => {
      const sender = ShieldedKeypair.generate();
      const recipient = ShieldedKeypair.generate();
      const oldViewingKey = recipient.viewingKey();
      const currentViewingKey = ViewingKey.fromBytes(bytes32(new Uint8Array(32).fill(17)));
      const nullifierKey = recipient.nullifierKey();
      const identity = ShieldedAddress.fromPublicKeys(
        recipient.signingPublicKey(),
        recipient.nullifierPublicKey(),
        currentViewingKey.publicKey(),
      );
      const local = LocalShieldedKeys.fromKeys({
        address: identity,
        viewingKeys: [currentViewingKey, oldViewingKey],
        nullifierKey,
      });
      const senderViewing = sender.viewingKey();
      const firstNullifier = bytes32(new Uint8Array(32).fill(21));
      const tx = senderViewing.transactionViewingKey(firstNullifier);
      const labels: DecryptLabel[] = [];
      const keys: ShieldedKeys = {
        address: () => local.address(),
        viewingPublicKeys: () => local.viewingPublicKeys(),
        decrypt: (requests) => {
          labels.push(...requests.map((request) => request.label));
          return local.decrypt(requests);
        },
        derive: (requests) => local.derive(requests),
        transactionKeys: (requests) => local.transactionKeys(requests),
      };
      try {
        const outputs = modes.map((mode, index) =>
          createProofOutput({
            ownerAddress: recipient.shieldedAddress(),
            asset: SOL_MINT,
            mint: Mint.fromRegistry(new AssetRegistry(), SOL_MINT),
            amount: BigInt((index + 1) * 11),
            blinding: bytes32(new Uint8Array(32).fill(index + 3)),
            encryptionMode: mode,
          }),
        );
        const salt = bytes16(new Uint8Array(16).fill(7));
        const encrypted = encodeConfidentialSlots(outputs, new AssetRegistry(), tx, salt);
        const transaction: IndexedShieldedTransaction = {
          slot: 1n,
          txSignature: signature("1".repeat(64)),
          txViewingPublicKey: tx.publicKey(),
          salt,
          outputSlots: outputs.map((output, index) => {
            const sealed = encrypted[index];
            if (sealed === undefined) throw new Error("missing ciphertext");
            return {
              viewTag: sealed.viewTag,
              payload: sealed.data,
              outputContext: {
                hash: output.hash(DEFAULT_TREE_ID),
                tree: treeAddress(DEFAULT_TREE_ID),
                leafIndex: BigInt(index),
              },
            };
          }),
          messages: [],
          nullifiers: [firstNullifier],
          proofless: false,
        };
        const wallet = new Wallet({ identity });
        const report = await decryptTransactions({ wallet, keys, transactions: [transaction] });
        expect({
          count: report.storedUtxos,
          balance: wallet.balance(SOL_MINT).amount,
          amounts: wallet.utxos().map((utxo) => utxo.utxo.amount),
          labels,
        }).toEqual({
          count: 3,
          balance: 66n,
          amounts: [11n, 22n, 33n],
          labels: modes.map((mode) =>
            mode === EncryptionMode.PoseidonKdf ? "poseidonKdfUtxo" : "transfer",
          ),
        });
        const poseidonIndex = modes.indexOf(EncryptionMode.PoseidonKdf);
        expect(poseidonIndex).toBeGreaterThanOrEqual(0);
        for (const mutation of ["encoding", "recipientKey"]) {
          const changed: IndexedShieldedTransaction = {
            ...transaction,
            outputSlots: transaction.outputSlots.map((slot, index) => {
              if (index !== poseidonIndex) return slot;
              let changedFrame: Uint8Array;
              if (mutation === "encoding") {
                changedFrame = slot.payload.slice();
                changedFrame[0] = 2;
              } else {
                const frame = decodeOutputData(slot.payload);
                const body = frame.body.slice();
                body.set(currentViewingKey.publicKey().toBytes());
                changedFrame = encodeOutputData(frame.scheme, body);
              }
              return { ...slot, payload: changedFrame };
            }),
          };
          const fresh = new Wallet({ identity });
          await decryptTransactions({ wallet: fresh, keys, transactions: [changed] });
          expect(fresh.utxos().map((utxo) => utxo.utxo.amount)).toEqual(
            outputs.filter((_, index) => index !== poseidonIndex).map((output) => output.amount),
          );
        }
      } finally {
        local.destroy();
        nullifierKey.destroy();
        oldViewingKey.destroy();
        currentViewingKey.destroy();
        tx.destroy();
        senderViewing.destroy();
        sender.destroy();
        recipient.destroy();
      }
    });
  }
});
