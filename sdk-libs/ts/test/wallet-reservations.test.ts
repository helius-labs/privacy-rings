import { address, blockhash, signature, type Address, type Blockhash } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizedPrivateTransaction } from "../src/client/client.js";
import { LocalKeys } from "../src/client/keys.js";
import type { PrivateTransactionClient } from "../src/wallet/index.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
} from "../src/transaction/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { extendReservation } from "../src/flows/reserve.js";
import { createSplit, createTransfer } from "../src/wallet/actions.js";
import { createMerge } from "../src/wallet/merge.js";
import { buildTransferTransaction } from "../src/wallet/transactions.js";
import { syncWallet } from "../src/wallet/sync.js";
import {
  kitReads,
  matchesPage,
  privateTransactionClient,
  syncReads,
  transactionsPage,
} from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";
import { transactionItems } from "./helpers/pages.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TRANSACTION = emptyTransaction(PAYER);

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

function localKeys(keypair: ShieldedKeypair): LocalKeys {
  return LocalKeys.fromKeypair(keypair, {
    prove: () => Promise.reject(new Error("prove must not be called")),
    proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
  });
}

function fundedWallet(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  ringBound: readonly number[] = [],
): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) =>
      walletUtxo(keypair, amount, index, ringBound.includes(index)),
    ),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function walletUtxo(keypair: ShieldedKeypair, amount: bigint, index: number, ringBound = false) {
  return {
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
      data: new Data(),
      ...(ringBound ? { ringProgramId: PAYER } : {}),
    }),
    outputContext: {
      hash: filled(index + 1),
      tree: TREE,
      leafIndex: BigInt(index),
    },
    nullifier: filled(index + 20),
    spent: false,
  };
}

function transferParams(wallet: Wallet, amount: bigint) {
  return {
    wallet,
    payer: PAYER,
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    asset: SOL_MINT as Address,
    amount,
  };
}

function buildParams(client: PrivateTransactionClient, wallet: Wallet, keypair: ShieldedKeypair) {
  return {
    client,
    wallet,
    keys: localKeys(keypair),
    feePayer: keypair.shieldedAddress().solanaAddress(),
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    amount: 3n,
  };
}

function assemblingClient(): Readonly<{
  client: PrivateTransactionClient;
  assemble: ReturnType<typeof vi.fn>;
}> {
  const assemble = vi.fn(
    async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) => TRANSACTION,
  );
  return {
    client: privateTransactionClient({
      getAccount: vi.fn(async () => undefined),
      assembleAuthorizedPrivateTransaction: assemble,
    }),
    assemble,
  };
}

describe("UTXO reservations", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("holds created inputs against a second selection", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
  });

  it("restores an uncertain submission and frees its inputs only after finalized expiry and fresh nullifier sync", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const input = wallet.utxos()[0]!;
    const genesisHash = address("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG");
    const reservation = wallet._reserveUtxos({
      utxoHashes: [input.outputContext.hash],
      nowMs: 1n,
      ttlMs: 120_000n,
    });
    const pending = {
      id: reservation.id,
      intentHash: filled(2),
      signature: signature("1".repeat(64)),
      genesisHash,
      blockhash: blockhash("1".repeat(32)),
      blockhashValidAtSlot: 500n,
      lastValidBlockHeight: 240n,
    };
    expect(wallet._beginSubmission(pending, 2n)).toBe(true);
    const snapshot = serializeWallet(wallet);
    const missingSlot = snapshot.replace(',"blockhashValidAtSlot":"500"', "");
    expect(() => deserializeWallet(missingSlot)).toThrow("TRANSACTION_DESERIALIZE");
    const previous = deserializeWallet(
      missingSlot.replace(`,"blockhash":"${pending.blockhash}"`, ""),
    );
    expect(previous.pendingSubmissions()).toMatchObject([
      { genesisHash, signature: pending.signature },
    ]);
    expect(previous._activeReservations(1_000_000n)).toHaveLength(1);
    const restored = deserializeWallet(snapshot);
    expect(restored.pendingSubmissions()).toEqual([
      {
        ...pending,
        attempts: 1,
        utxoHashes: [input.outputContext.hash],
      },
    ]);
    expect(restored._activeReservations(1_000_000n)).toHaveLength(1);

    let indexerSlot = 400n;
    let blockHeight = 241n;
    let finalizedSlot = 499n;
    let blockhashSlot = 500n;
    let signatureHistorySlot = 501n;
    let indexedSpend = false;
    let stillValid = false;
    let signatureStatus: {
      slot: bigint;
      confirmationStatus: "confirmed" | "finalized";
      err: string | null;
    } | null = null;
    let chain: Address = PAYER;
    let switchChainDuringScan = false;
    const context = () => ({ slot: indexerSlot, blockTime: 1_700_000_000n });
    const checkBlockhash = vi.fn((checked: Blockhash, config: unknown) => ({
      send: async () => {
        expect(checked).toBe(pending.blockhash);
        expect(config).toEqual({ commitment: "finalized", minContextSlot: finalizedSlot });
        return { context: { slot: blockhashSlot }, value: stillValid };
      },
    }));
    const checkSignature = vi.fn((signatures: readonly string[], config: unknown) => ({
      send: async () => {
        expect(signatures).toEqual([pending.signature]);
        expect(config).toEqual({ searchTransactionHistory: true });
        return { context: { slot: signatureHistorySlot }, value: [signatureStatus] };
      },
    }));
    const client = {
      ...syncReads({
        getShieldedTransactionsByTags: async () =>
          transactionsPage({ context: { ...context(), slot: 500n } }),
        getEncryptedUtxosByTags: async () => matchesPage({ context: { ...context(), slot: 500n } }),
        getShieldedTransactionsByNullifiers: async () => {
          if (switchChainDuringScan) chain = PAYER;
          return transactionsPage({
            context: context(),
            data: transactionItems(
              indexedSpend
                ? [
                    {
                      slot: 500n,
                      txSignature: pending.signature,
                      proofless: false,
                      messages: [],
                      nullifiers: [input.nullifier],
                      outputSlots: [],
                    },
                  ]
                : [],
            ),
          });
        },
      }),
      ...kitReads({
        solanaRpc: {
          getGenesisHash: () => ({ send: async () => chain }),
          getEpochInfo: (config: unknown) => ({
            send: async () => {
              expect(config).toEqual({ commitment: "finalized" });
              return { absoluteSlot: finalizedSlot, blockHeight };
            },
          }),
          isBlockhashValid: checkBlockhash,
          getSignatureStatuses: checkSignature,
        },
      }),
    };
    const sync = (wallet = restored) => syncWallet({ wallet, keys: localKeys(keypair), client });
    const before = serializeWallet(restored);
    await expect(sync()).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_DECRYPTION_NETWORK_MISMATCH",
    });
    expect(serializeWallet(restored)).toBe(before);

    chain = genesisHash;
    indexerSlot = 500n;
    await sync();
    expect(restored.pendingSubmissions()).toHaveLength(1);
    expect(checkBlockhash).not.toHaveBeenCalled();
    await expect(createTransfer(transferParams(restored, 3n))).rejects.toMatchObject({
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });

    finalizedSlot = 500n;
    blockHeight = 240n;
    await sync();
    expect(restored.pendingSubmissions()).toHaveLength(1);
    expect(checkBlockhash).not.toHaveBeenCalled();

    blockHeight = 241n;
    stillValid = true;
    await sync();
    expect(restored.pendingSubmissions()).toHaveLength(1);
    expect(checkBlockhash).toHaveBeenCalledOnce();

    stillValid = false;
    blockhashSlot = 499n;
    const beforeStaleReply = serializeWallet(restored);
    await expect(sync()).rejects.toMatchObject({ code: "WALLET_SYNC", causeCode: "CLIENT_RPC" });
    expect(serializeWallet(restored)).toBe(beforeStaleReply);

    blockhashSlot = 501n;
    signatureHistorySlot = 500n;
    await expect(sync()).rejects.toMatchObject({ code: "WALLET_SYNC", causeCode: "CLIENT_RPC" });
    expect(serializeWallet(restored)).toBe(beforeStaleReply);
    signatureHistorySlot = 501n;

    await sync();
    expect(restored.pendingSubmissions()).toHaveLength(1);
    expect(restored._activeReservations(1_000_000n)).toHaveLength(1);

    indexerSlot = 501n;
    for (const status of [
      { slot: 500n, confirmationStatus: "finalized", err: null },
      { slot: 500n, confirmationStatus: "confirmed", err: "AccountNotFound" },
    ] as const) {
      const unresolved = deserializeWallet(serializeWallet(restored));
      signatureStatus = status;
      await sync(unresolved);
      expect(unresolved.pendingSubmissions()).toHaveLength(1);
      expect(unresolved._activeReservations(1_000_000n)).toHaveLength(1);
    }
    const succeeded = deserializeWallet(serializeWallet(restored));
    signatureStatus = { slot: 500n, confirmationStatus: "finalized", err: null };
    await sync(succeeded);
    indexedSpend = true;
    await sync(succeeded);
    expect(succeeded.pendingSubmissions()).toEqual([]);
    expect(succeeded.utxos()[0]?.spent).toBe(true);
    indexedSpend = false;

    stillValid = true;
    await sync();
    stillValid = false;

    signatureStatus = { slot: 500n, confirmationStatus: "finalized", err: "AccountNotFound" };
    indexerSlot = 500n;
    await sync();
    expect(restored.pendingSubmissions()).toHaveLength(1);

    indexerSlot = 501n;
    const absent = deserializeWallet(serializeWallet(restored));
    signatureStatus = null;
    const beforeNetworkChange = serializeWallet(absent);
    switchChainDuringScan = true;
    await expect(sync(absent)).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_DECRYPTION_NETWORK_MISMATCH",
    });
    expect(serializeWallet(absent)).toBe(beforeNetworkChange);
    expect(absent._activeReservations(1_000_000n)).toHaveLength(1);
    switchChainDuringScan = false;
    chain = genesisHash;
    await sync(absent);
    expect(absent.pendingSubmissions()).toEqual([]);
    signatureStatus = { slot: 500n, confirmationStatus: "finalized", err: "AccountNotFound" };
    await sync();
    expect(restored.pendingSubmissions()).toEqual([]);
    expect(restored._activeReservations(1_000_000n)).toEqual([]);
    await expect(createTransfer(transferParams(restored, 3n))).resolves.toBeDefined();
  });

  it("lets exactly one of two concurrent builds spend a UTXO", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const { client, assemble } = assemblingClient();
    const results = await Promise.allSettled([
      buildTransferTransaction(buildParams(client, wallet, keypair)),
      buildTransferTransaction(buildParams(client, wallet, keypair)),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(assemble).toHaveBeenCalledTimes(1);
    const failed = results.find((result) => result.status === "rejected");
    expect(failed?.reason).toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"],
    });
  });

  it("releases the reservation when the build fails", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const { client, assemble } = assemblingClient();
    assemble.mockRejectedValueOnce(new Error("assembly down"));
    await expect(
      buildTransferTransaction(buildParams(client, wallet, keypair)),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("frees the UTXOs after the reservation expires", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    now.mockReturnValue(1_000_000 + 119_999);
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
    now.mockReturnValue(1_000_000 + 120_000);
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("keeps an extended reservation past its first expiry", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    const reservation = wallet._reservationEntries()[0];
    if (reservation === undefined) throw new Error("reservation");
    now.mockReturnValue(1_000_000 + 100_000);
    extendReservation(wallet, reservation.id);
    now.mockReturnValue(1_000_000 + 200_000);
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
    now.mockReturnValue(1_000_000 + 220_000);
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("drops the reservation when sync marks its UTXO spent", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    expect(wallet._reservationEntries()).toHaveLength(1);
    wallet._replace({
      utxos: [{ ...walletUtxo(keypair, 5n, 0), spent: true }],
      transactions: [],
      nullifiers: new Set(),
    });
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("round-trips reservations through serialization", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    const serialized = serializeWallet(wallet);
    const restored = deserializeWallet(serialized);
    await expect(createTransfer(transferParams(restored, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
    const { reservations, ...withoutReservations } = JSON.parse(serialized) as Record<
      string,
      unknown
    >;
    expect(reservations).toHaveLength(1);
    const accepted = deserializeWallet(JSON.stringify(withoutReservations));
    await expect(createTransfer(transferParams(accepted, 3n))).resolves.toBeDefined();
  });

  it("releases at once when merge preparation refuses the UTXOs", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n], [1]);
    await expect(
      createMerge({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(keypair),
        asset: SOL_MINT,
        inputs: [filled(1), filled(2)],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_MERGE_INPUT_RING_MISMATCH" });
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("refuses named inputs another build reserved", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n]);
    await createTransfer(transferParams(wallet, 5n));
    expect(() =>
      createSplit({ wallet, payer: PAYER, asset: SOL_MINT, parts: 2, input: filled(1) }),
    ).toThrowError(expect.objectContaining({ code: "WALLET_NOTE_RESERVED" }));
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    await expect(
      createMerge({ wallet, keys, asset: SOL_MINT, inputs: [filled(1), filled(2)] }),
    ).rejects.toMatchObject({ code: "WALLET_NOTE_RESERVED" });
    await expect(createMerge({ wallet, keys, asset: SOL_MINT })).rejects.toMatchObject({
      code: "WALLET_NOTHING_TO_MERGE",
    });
  });
});
