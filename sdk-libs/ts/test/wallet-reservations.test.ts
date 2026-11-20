import { AccountRole, address, type Address } from "@solana/kit";
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
import {
  buildRingPaymentTransaction,
  buildTransferTransaction,
} from "../src/wallet/transactions.js";
import type { RingTransfers } from "../src/client/ports.js";
import {
  ConfidentialTransfer,
  WithdrawalTarget,
  type SppProofInputs,
} from "../src/transaction/instructions/transact.js";
import { proofInputFromEntry } from "../src/wallet/private-transaction.js";
import type { ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { approveUnattended } from "../src/transaction/wallet/intent.js";
import { BLOCKHASH, privateTransactionClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";

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
      treeId: 0,
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

describe("ring payments", () => {
  const RING = address("So11111111111111111111111111111111111111112");
  const RING_OTHER = address("Stake11111111111111111111111111111111111111");
  type Request = Parameters<RingTransfers["proveRingTransfer"]>[0];

  type Tamper = (request: Request) => Promise<Fault | void>;
  type Fault = Readonly<{
    proofInputs?: SppProofInputs;
    skip?: true;
    programAddress?: Address;
    signer?: Address;
  }>;

  function ring(keypair: ShieldedKeypair, tamper: Tamper = async () => {}): RingTransfers {
    return {
      ringProgramId: RING,
      proveRingTransfer: async (request) => {
        const { transfer, payment } = request;
        transfer.send(payment.recipient, payment.asset, payment.amount);
        const fault = (await tamper(request)) ?? {};
        if (fault.skip !== true)
          await request.authorize(fault.proofInputs ?? transfer.sign(keypair, new AssetRegistry()));
        return {
          instruction: {
            programAddress: fault.programAddress ?? RING,
            accounts: [{ address: fault.signer ?? PAYER, role: AccountRole.WRITABLE_SIGNER }],
          },
          computeUnitLimit: 1_400_000,
        };
      },
    };
  }

  /** Pays the request from a note core did not reserve. */
  function anotherNote({ payment, keys }: Request): SppProofInputs {
    const other = new ConfidentialTransfer(
      keys.address(),
      [proofInputFromEntry(walletUtxo(spendingKeypair(), 50n, 1), keys.address())],
      PAYER,
    ).withRingProgramId(RING);
    other.send(payment.recipient, payment.asset, payment.amount);
    return other.sign(spendingKeypair(), new AssetRegistry());
  }

  function ringPayment(
    wallet: Wallet,
    keypair: ShieldedKeypair,
    transfers: RingTransfers,
    inProof = true,
  ) {
    const approvals: ApprovalRequest[] = [];
    const build = buildRingPaymentTransaction({
      client: { getLatestBlockhash: async () => BLOCKHASH },
      ring: transfers,
      wallet,
      keys: localKeys(keypair),
      feePayer: PAYER,
      ...(inProof ? { owner: keypair } : {}),
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 30n,
      approve: (request) => {
        approvals.push(request);
        return approveUnattended(request);
      },
    });
    return { build, approvals };
  }

  it("signs the checked payment for its in-proof owner and compiles the ring instruction", async () => {
    const keypair = spendingKeypair();
    const sign = vi.spyOn(keypair, "sign");
    const { build, approvals } = ringPayment(fundedWallet(keypair, [100n]), keypair, ring(keypair));

    await expect(build).resolves.toBeDefined();
    expect(sign).toHaveBeenCalledOnce();
    expect(approvals.map((request) => request.intent)).toMatchObject([
      {
        kind: "ringTransfer",
        ringProgramId: RING,
        amount: 30n,
        boundary: "entry",
        defaultFunding: 100n,
      },
    ]);
  });

  it.each<readonly [string, Readonly<{ field: string; signed: number }>, Tamper]>([
    [
      "an output to a third party",
      { field: "recipient", signed: 0 },
      async ({ transfer }: Request) => {
        transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 10n);
      },
    ],
    [
      "a settlement leg",
      { field: "settlements", signed: 0 },
      async ({ transfer }: Request) => {
        transfer.withdraw(SOL_MINT, 10n, WithdrawalTarget.sol({ recipient: PAYER }));
      },
    ],
    [
      "another note than the reserved one",
      { field: "inputs", signed: 0 },
      async (request: Request) => ({ proofInputs: anotherNote(request) }),
    ],
    [
      "a retry after a refused authorization",
      { field: "authorization", signed: 0 },
      async (request: Request) =>
        void (await request.authorize(anotherNote(request)).catch(() => undefined)),
    ],
    [
      "a concurrent authorization",
      { field: "authorization", signed: 1 },
      async ({ transfer, authorize }: Request) =>
        void authorize(transfer.sign(spendingKeypair(), new AssetRegistry())),
    ],
    ["no authorization", { field: "authorization", signed: 0 }, async () => ({ skip: true })],
    [
      "a second authorization",
      { field: "authorization", signed: 1 },
      async ({ transfer, authorize }: Request) => {
        await authorize(transfer.sign(spendingKeypair(), new AssetRegistry()));
      },
    ],
    [
      "another program",
      { field: "program", signed: 1 },
      async () => ({ programAddress: RING_OTHER }),
    ],
    ["another signer", { field: "signers", signed: 1 }, async () => ({ signer: RING_OTHER })],
  ] as const)(
    "refuses %s, the notes stay reserved only once the owner signed",
    async (_, refusal, tamper) => {
      const keypair = spendingKeypair();
      const sign = vi.spyOn(keypair, "sign");
      const wallet = fundedWallet(keypair, [100n]);
      await expect(ringPayment(wallet, keypair, ring(keypair, tamper)).build).rejects.toMatchObject(
        {
          code: "WALLET_BUILD_RING_PAYMENT",
          cause: { code: "WALLET_INTENT_MISMATCH", details: { field: refusal.field } },
        },
      );
      expect(sign).toHaveBeenCalledTimes(refusal.signed);
      const spend = createTransfer(transferParams(wallet, 100n));
      await (refusal.signed === 0
        ? expect(spend).resolves.toBeDefined()
        : expect(spend).rejects.toMatchObject({ causeCode: "WALLET_INSUFFICIENT_BALANCE" }));
    },
  );

  it("releases the notes when a public-owner payment fails after authorization", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const foreign = ring(keypair, async () => ({ programAddress: RING_OTHER }));
    await expect(ringPayment(wallet, keypair, foreign, false).build).rejects.toMatchObject({
      cause: { details: { field: "program" } },
    });
    await expect(createTransfer(transferParams(wallet, 100n))).resolves.toBeDefined();
  });

  it.each<readonly [string, Tamper]>([
    ["a decryption", async ({ keys }) => void (await keys.decrypt([]))],
    [
      "a proof of another note",
      async ({ keys }) =>
        void (await Reflect.apply(keys.prove, keys, [
          { circuit: "transfer", payload: { inputs: [{ isDummy: 0n, nullifier: 1n }] } },
        ])),
    ],
  ])("withholds %s from the ring", async (_, tamper) => {
    const keypair = spendingKeypair();
    await expect(
      ringPayment(fundedWallet(keypair, [100n]), keypair, ring(keypair, tamper)).build,
    ).rejects.toMatchObject({ cause: { code: "WALLET_RING_KEY_WITHHELD" } });
  });
});
