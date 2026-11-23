import {
  address,
  assertIsFullySignedTransaction,
  generateKeyPairSigner,
  getAddressEncoder,
  getSignatureFromTransaction,
  signTransactionWithSigners,
  type Address,
  type Blockhash,
  type Transaction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { LocalKeys } from "../src/client/keys.js";
import { ClientError } from "../src/client/error.js";
import { prepareMerge } from "../src/client/prover/merge.js";
import { USER_REGISTRY_PROGRAM_ID } from "../src/interface/program.js";
import { internalUserRecordPda } from "../src/wallet/registry.js";
import {
  authorizedPrivateTransactionMaterial,
  type AuthorizedPrivateTransaction,
  type ProofDataSource,
  type ProofService,
  type TransactionBroadcaster,
} from "../src/client/ports.js";
import type { DepositClient } from "../src/wallet/index.js";
import {
  SPL_TOKEN_2022_PROGRAM_ID,
  type Bytes32,
  type Bytes128,
  type RequestContext,
} from "../src/interface/index.js";
import {
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  type ViewingKey,
} from "../src/keypair/index.js";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  decryptToBalances,
  deserializeWallet,
  serializeWallet,
  type ShieldedKeys,
} from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import {
  createMultiTransfer,
  createSplit,
  createTransfer,
  createWithdrawal,
  resolveWithdrawal,
} from "../src/wallet/actions.js";
import {
  associatedTokenAddress,
  splInterfaceWithBump,
  treeAddress,
} from "../src/interface/pda/index.js";
import { ownerSignerAddresses } from "../src/client/prover/assembly.js";
import { buildDepositTransaction, createDeposit } from "../src/wallet/deposit.js";
import { loadPersistedWallet } from "../src/wallet/persisted.js";
import { walletSnapshotCipher } from "../src/wallet/snapshot-cipher.js";
import { depositClient, privateTransactionClient, registryReads } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";
import { approveIntent, type ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { MAX_SPEND_INPUTS } from "../src/flows/select.js";
import { withdrawalSetupInstructions } from "../src/flows/settlement.js";
import { buildMergeTransaction, createMerge, type MergeClient } from "../src/wallet/merge.js";
import {
  authorizePrivateTransaction,
  proofInputFromEntry,
} from "../src/wallet/private-transaction.js";
import {
  buildMultiTransferTransaction,
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
} from "../src/wallet/transactions.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const TRANSACTION = emptyTransaction(PAYER);

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

/** Unit tests never reach the prover; the keys still need one to exist. */
function stubProofs(): ProofService {
  return {
    prove: vi.fn(async () => {
      throw new Error("prove must not be called");
    }),
    proveMerge: vi.fn(async () => {
      throw new Error("proveMerge must not be called");
    }),
  };
}

function localKeys(keypair: ShieldedKeypair): LocalKeys {
  return LocalKeys.fromKeypair(keypair, stubProofs());
}

/** Records every approval a build asks for and grants it. */
function recordingApproval(): Readonly<{
  approve: (request: ApprovalRequest) => Promise<ReturnType<typeof approveIntent>>;
  requests: ApprovalRequest[];
}> {
  const requests: ApprovalRequest[] = [];
  return {
    approve: (request) => {
      requests.push(request);
      return Promise.resolve(approveIntent(request.intent));
    },
    requests,
  };
}

/** Every per-transaction key a build mints, so a test can check they were wiped. */
function captureTransactionKeys(keys: LocalKeys): ViewingKey[] {
  const minted: ViewingKey[] = [];
  const mint = keys.transactionKeys.bind(keys);
  vi.spyOn(keys, "transactionKeys").mockImplementation(async (requests) => {
    const result = await mint(requests);
    minted.push(...result);
    return result;
  });
  return minted;
}

function fundedWallet(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  options: Readonly<{ asset?: Address; ringProgramId?: Address }> = {},
): Wallet {
  const asset = options.asset ?? SOL_MINT;
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
        data: new Data(),
        ...(options.ringProgramId === undefined ? {} : { ringProgramId: options.ringProgramId }),
      }),
      outputContext: {
        hash: filled(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function latestBlockhashClient(feeTree = TREE): DepositClient {
  return depositClient({
    tree: feeTree,
    getLatestBlockhash: vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    })),
  });
}

function capturePrivateBuild(transaction = TRANSACTION): Readonly<{
  client: ReturnType<typeof privateTransactionClient> & TransactionBroadcaster;
  assemble: ReturnType<typeof vi.fn>;
}> {
  const assemble = vi.fn(
    async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) => transaction,
  );
  return {
    client: {
      ...privateTransactionClient({
        getAccount: vi.fn(async () => undefined),
        assembleAuthorizedPrivateTransaction: assemble,
      }),
      async broadcastTransaction() {
        throw new Error("unexpected RPC broadcast");
      },
      async getBlockhashValidity() {
        return { slot: 1n, valid: true };
      },
    },
    assemble,
  };
}

describe("private transaction construction", () => {
  it("rejects zero-value public actions before building them", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      buildDepositTransaction({
        client: latestBlockhashClient(),
        feePayer: PAYER,
        recipient: keypair.shieldedAddress(),
        amount: 0n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_DEPOSIT",
      causeCode: "WALLET_CREATE_DEPOSIT",
      causeCodes: ["WALLET_CREATE_DEPOSIT", "WALLET_INVALID_AMOUNT"],
    });
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 0n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_AMOUNT" });
  });

  it("covers a withdrawal with the largest UTXOs first", async () => {
    const keypair = ShieldedKeypair.generate();
    const created = await createWithdrawal({
      wallet: fundedWallet(keypair, [20n, 40n, 80n]),
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });
    expect(created.transaction.inputCount()).toBe(1);
    expect(created.transaction.tree()).toBe(TREE);
  });

  it("refuses a default-rail cover wider than the shape cap", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(
          keypair,
          Array.from({ length: MAX_SPEND_INPUTS + 1 }, () => 10n),
        ),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 10n * BigInt(MAX_SPEND_INPUTS + 1),
      }),
    ).rejects.toMatchObject({
      code: "WALLET_TOO_MANY_INPUTS",
      details: { got: MAX_SPEND_INPUTS + 1, max: MAX_SPEND_INPUTS },
    });
  });

  it("reports the full spendable balance when a cover falls short", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [10n, 15n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 60n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_INSUFFICIENT_BALANCE",
      details: { requested: "60", available: "25" },
    });
  });

  it("authorizes an Ed25519 spend whose fee payer sponsors the owner", async () => {
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(7)));
    const wallet = fundedWallet(keypair, [100n]);
    const created = await createWithdrawal({
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });

    const material = authorizedPrivateTransactionMaterial(
      await authorizePrivateTransaction(
        created.transaction,
        wallet,
        LocalShieldedKeys.fromKeypair(keypair),
      ),
    );
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.proofInputs.payer).toBe(PAYER);
    expect(
      ownerSignerAddresses(material.proofInputs.inputUtxos, material.proofInputs.outputs),
    ).toEqual([keypair.shieldedAddress().solanaAddress()]);
  });

  it("does not spend ring-bound UTXOs through a default-ring action", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n], { ringProgramId: RING }),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 50n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INSUFFICIENT_BALANCE" });
  });

  it("refuses to turn an unregistered private recipient into a public withdrawal", async () => {
    const keypair = ShieldedKeypair.generate();
    const getAccount = vi.fn(async () => undefined);
    await expect(
      createTransfer({
        client: { getAccount },
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 10n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_RECIPIENT_NOT_REGISTERED",
    });
    expect(getAccount).toHaveBeenCalledOnce();
  });

  it("accepts an already-resolved shielded recipient without an RPC read", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const created = await createTransfer({
      wallet: fundedWallet(sender, [100n]),
      payer: PAYER,
      recipient,
      asset: SOL_MINT,
      amount: 10n,
    });
    expect(created.recipient).toMatchObject({
      kind: "shielded",
      address: recipient,
    });
  });

  const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
  const otherGenesis = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
  it("uses verified service keys after a successful registry miss", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const address = vi.fn(async () => recipient);
    const context = { signal: new AbortController().signal };
    const created = await createTransfer(
      {
        client: { ...registryReads(), getGenesisHash: async () => genesisHash },
        decryptionService: { address, genesisHash },
        wallet: fundedWallet(ShieldedKeypair.generate(), [100n]),
        payer: PAYER,
        recipient: recipient.solanaAddress(),
        asset: SOL_MINT,
        amount: 10n,
      },
      context,
    );
    expect(created.recipient.address).toBe(recipient);
    expect(address).toHaveBeenCalledWith(recipient.solanaAddress(), context);
  });

  it("uses the registered wallet before invoking a decryption provider", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const owner = recipient.solanaAddress();
    const pda = await internalUserRecordPda(owner);
    const record = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(owner),
      pda.bump,
      ...recipient.nullifierPublicKey,
      ...recipient.viewingPublicKey.toBytes(),
      0,
    );
    const address = vi.fn(async () => ShieldedKeypair.generate().shieldedAddress());
    const getGenesisHash = vi.fn(async () => otherGenesis);
    const result = await createTransfer({
      wallet: fundedWallet(ShieldedKeypair.generate(), [100n]),
      client: {
        ...registryReads(async () => ({
          owner: USER_REGISTRY_PROGRAM_ID,
          data: record,
          lamports: 1n,
        })),
        getGenesisHash,
      },
      decryptionService: { address, genesisHash },
      recipient: owner,
      payer: PAYER,
      asset: SOL_MINT,
      amount: 10n,
    });
    expect(result.recipient.kind).toBe("registered");
    expect(result.recipient.address.toBytes()).toEqual(recipient.toBytes());
    expect(address).not.toHaveBeenCalled();
    expect(getGenesisHash).not.toHaveBeenCalled();
  });

  it("keeps a verified miss's context for the registry read after service lookup", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const serviceAddress = vi.fn(async () => recipient);
    const getAccountWithContext = vi
      .fn()
      .mockResolvedValueOnce({ account: undefined, slot: 10n })
      .mockResolvedValueOnce({ account: undefined, slot: 9n });
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    await expect(
      createTransfer({
        client: {
          ...registryReads(),
          getAccountWithContext,
          getGenesisHash: async () => genesisHash,
        },
        decryptionService: { address: serviceAddress, genesisHash },
        wallet,
        recipient: recipient.solanaAddress(),
        payer: PAYER,
        asset: SOL_MINT,
        amount: 10n,
      }),
    ).rejects.toMatchObject({ causeCode: "WALLET_RECIPIENT_CONTEXT_STALE" });
    expect(getAccountWithContext.mock.calls.map((args) => args[1])).toEqual([0n, 10n]);
    expect(serviceAddress).toHaveBeenCalledOnce();
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it("leaves spend state intact on registry failure or a mismatched service address", async () => {
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    const address = vi.fn(async () => ShieldedKeypair.generate().shieldedAddress());
    const input = {
      decryptionService: { address, genesisHash },
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 10n,
    };
    await expect(
      createTransfer({
        ...input,
        client: {
          ...registryReads(async () => {
            throw new Error("RPC unavailable");
          }),
          getGenesisHash: async () => genesisHash,
        },
      }),
    ).rejects.toMatchObject({ code: "WALLET_CREATE_TRANSFER" });
    expect(address).not.toHaveBeenCalled();
    await expect(
      createTransfer({
        ...input,
        client: { ...registryReads(), getGenesisHash: async () => genesisHash },
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
    });
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it("uses a registration that appears during one shared lookup for a batch recipient", async () => {
    const registered = ShieldedKeypair.generate().shieldedAddress();
    const owner = registered.solanaAddress();
    const serviceKeys = ShieldedKeypair.generate().shieldedAddress();
    const fallback = ShieldedAddress.fromPublicKeys(
      registered.signingPublicKey,
      serviceKeys.nullifierPublicKey,
      serviceKeys.viewingPublicKey,
    );
    const pda = await internalUserRecordPda(owner);
    const record = {
      owner: USER_REGISTRY_PROGRAM_ID,
      lamports: 1n,
      data: Uint8Array.of(
        1,
        ...getAddressEncoder().encode(owner),
        pda.bump,
        ...registered.nullifierPublicKey,
        ...registered.viewingPublicKey.toBytes(),
        0,
      ),
    };
    let published = false;
    const getAccount = vi.fn(async () => (published ? record : undefined));
    const address = vi.fn(async () => {
      published = true;
      return fallback;
    });
    const result = await createMultiTransfer({
      client: { ...registryReads(getAccount), getGenesisHash: async () => genesisHash },
      decryptionService: { address, genesisHash },
      wallet: fundedWallet(ShieldedKeypair.generate(), [100n]),
      payer: PAYER,
      asset: SOL_MINT,
      payments: [5n, 10n].map((amount) => ({ recipient: owner, amount })),
    });
    expect(result.recipients.map((recipient) => recipient.kind)).toEqual([
      "registered",
      "registered",
    ]);
    expect(result.recipients.map(({ address }) => address.toBytes())).toEqual([
      registered.toBytes(),
      registered.toBytes(),
    ]);
    expect(result.recipientAssertions).toHaveLength(1);
    expect(result.recipientAssertions[0]?.data).toEqual(
      Uint8Array.of(
        3,
        ...sha256
          .create()
          .update(new TextEncoder().encode("spr/user-registry/payment-targets/v1"))
          .update(Uint8Array.from(getAddressEncoder().encode(pda.address)))
          .update(Uint8Array.of(1))
          .update(registered.nullifierPublicKey)
          .update(registered.viewingPublicKey.toBytes())
          .digest(),
      ),
    );
    expect(getAccount).toHaveBeenCalledTimes(2);
    expect(address).toHaveBeenCalledOnce();
  });

  it("rejects explicit keys that would override another output's resolved keys for the same owner", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const other = ShieldedKeypair.generate().shieldedAddress();
    const conflicting = ShieldedAddress.fromPublicKeys(
      recipient.signingPublicKey,
      recipient.nullifierPublicKey,
      other.viewingPublicKey,
    );
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    await expect(
      createMultiTransfer({
        client: {
          ...registryReads(async () => undefined),
          getGenesisHash: async () => genesisHash,
        },
        decryptionService: { address: async () => recipient, genesisHash },
        wallet,
        payer: PAYER,
        asset: SOL_MINT,
        payments: [
          { recipient: recipient.solanaAddress(), amount: 5n },
          { recipient: conflicting, amount: 10n },
        ],
      }),
    ).rejects.toMatchObject({ causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH" });
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it("reserves nothing when the final registry read fails after resolving valid service keys", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    const getAccount = vi
      .fn(async () => undefined)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("RPC unavailable"));
    const address = vi.fn(async () => recipient);
    await expect(
      createTransfer({
        client: { ...registryReads(getAccount), getGenesisHash: async () => genesisHash },
        decryptionService: { address, genesisHash },
        wallet,
        payer: PAYER,
        recipient: recipient.solanaAddress(),
        asset: SOL_MINT,
        amount: 10n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_FETCH_USER_RECORD",
    });
    expect(getAccount).toHaveBeenCalledTimes(2);
    expect(address).toHaveBeenCalledOnce();
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it("keeps the reservation state unchanged when registry or service lookup is cancelled", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    for (const cancelAt of ["registry", "network", "service"] as const) {
      const controller = new AbortController();
      const getAccount = vi.fn(async () => {
        if (cancelAt === "registry") controller.abort();
        return undefined;
      });
      const getGenesisHash = vi.fn(async () => {
        if (cancelAt === "network") controller.abort();
        return genesisHash;
      });
      const address = vi.fn(async () => {
        controller.abort();
        return recipient;
      });
      await expect(
        createTransfer(
          {
            client: { ...registryReads(getAccount), getGenesisHash },
            decryptionService: { address, genesisHash },
            wallet,
            payer: PAYER,
            recipient: recipient.solanaAddress(),
            asset: SOL_MINT,
            amount: 10n,
          },
          { signal: controller.signal },
        ),
      ).rejects.toMatchObject({
        code: "WALLET_CREATE_TRANSFER",
        causeCode: "WALLET_RECIPIENT_LOOKUP_ABORTED",
      });
      expect(address).toHaveBeenCalledTimes(cancelAt === "service" ? 1 : 0);
      expect(serializeWallet(wallet)).toEqual(before);
    }
  });

  it("refuses a mismatched or invalid genesis without reserving any inputs", async () => {
    const wallet = fundedWallet(ShieldedKeypair.generate(), [100n]);
    const before = serializeWallet(wallet);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const address = vi.fn(async () => recipient);
    for (const hash of [otherGenesis, "invalid"]) {
      await expect(
        createTransfer({
          client: { ...registryReads(), getGenesisHash: async () => hash },
          decryptionService: { address, genesisHash },
          wallet,
          payer: PAYER,
          recipient: recipient.solanaAddress(),
          asset: SOL_MINT,
          amount: 10n,
        }),
      ).rejects.toMatchObject({
        code: "WALLET_CREATE_TRANSFER",
        causeCode: "WALLET_DECRYPTION_NETWORK_MISMATCH",
      });
    }
    expect(address).not.toHaveBeenCalled();
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it("reads genesis once for a batch of unregistered recipients", async () => {
    const first = ShieldedKeypair.generate().shieldedAddress();
    const second = ShieldedKeypair.generate().shieldedAddress();
    const getGenesisHash = vi.fn(async () => genesisHash);
    const address = vi.fn(async (owner: Address) =>
      owner === first.solanaAddress() ? first : second,
    );
    const created = await createMultiTransfer({
      client: { ...registryReads(), getGenesisHash },
      decryptionService: { address, genesisHash },
      wallet: fundedWallet(ShieldedKeypair.generate(), [100n]),
      payer: PAYER,
      asset: SOL_MINT,
      payments: [first, second].map((recipient) => ({
        recipient: recipient.solanaAddress(),
        amount: 5n,
      })),
    });
    expect(created.recipients.map(({ address }) => address)).toEqual([first, second]);
    expect(getGenesisHash).toHaveBeenCalledOnce();
    expect(address).toHaveBeenCalledTimes(2);
  });

  it("keeps split and merge conservation in their internal intent models", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n, 100n]);
    const split = createSplit({
      wallet,
      payer: PAYER,
      asset: SOL_MINT,
      parts: 2,
      input: wallet.utxos()[2]!.outputContext.hash,
    });
    const merge = await createMerge({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      asset: SOL_MINT,
    });
    expect(split).toMatchObject({ numOutputs: 2, perOutputAmount: 50n });
    expect(merge).toMatchObject({ numInputs: 2, mergedAmount: 50n });
  });

  it("pads named merge inputs to the narrowest proof and refuses more than 52", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(
      keypair,
      Array.from({ length: 53 }, (_, index) => BigInt(index + 1)),
    );
    const hashes = wallet.utxos().map((entry) => entry.outputContext.hash);
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    for (const [count, width] of [
      [8, 8],
      [9, 24],
      [24, 24],
      [25, 52],
      [52, 52],
    ] as const) {
      const merge = await createMerge({
        wallet,
        keys,
        asset: SOL_MINT,
        inputs: hashes.slice(0, count),
      });
      expect(merge.numInputs).toBe(count);
      expect(merge.prepared.inputs).toHaveLength(width);
      wallet._releaseReservation(merge.reservationId);
    }
    await expect(
      createMerge({ wallet, keys, asset: SOL_MINT, inputs: hashes }),
    ).rejects.toMatchObject({
      code: "WALLET_TOO_MANY_INPUTS",
      details: { got: 53, max: 52 },
    });
  });

  it("pads a merge with compact slots that each take a dummy nullifier", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n, 40n]);
    const keys = LocalShieldedKeys.fromKeypair(keypair);

    const merge = await createMerge({ wallet, keys, asset: SOL_MINT });
    expect(merge.prepared.inputs.map((input) => input.isCompact())).toEqual([
      false,
      false,
      false,
      ...Array.from({ length: 5 }, () => true),
    ]);
    expect(merge.prepared.dummyNullifiers()).toHaveLength(5);
  });
});

describe("prover indexer lag", () => {
  /** Builds a transfer or merge whose prover lags `lags` times before it answers. */
  async function build(
    kind: "transfer" | "merge",
    proofDataSource: ProofDataSource,
    lags: number,
    context?: RequestContext,
  ) {
    const keypair = spendingKeypair();
    const shielded = keypair.shieldedAddress();
    const owner = shielded.solanaAddress();
    const wallet = fundedWallet(keypair, [20n, 30n]);
    let calls = 0;
    const answer = async <T>(value: () => T): Promise<T> => {
      if (calls++ < lags) throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
      return value();
    };
    const keys = localKeys(keypair);
    try {
      if (kind === "transfer") {
        const result = await buildTransferTransaction(
          {
            client: privateTransactionClient({
              proofDataSource,
              assembleAuthorizedPrivateTransaction: () => answer(() => TRANSACTION),
            }),
            wallet,
            keys,
            feePayer: owner,
            recipient: ShieldedKeypair.generate().shieldedAddress(),
            amount: 25n,
          },
          context,
        ).catch((cause: unknown) => cause);
        return { result, calls, wallet };
      }
      const pda = await internalUserRecordPda(owner);
      const record = Uint8Array.of(
        1,
        ...getAddressEncoder().encode(owner),
        pda.bump,
        ...shielded.nullifierPublicKey,
        ...shielded.viewingPublicKey.toBytes(),
        1,
      );
      const result = await buildMergeTransaction(
        {
          client: {
            proofDataSource,
            tree: TREE,
            treeId: 0,
            getAccount: vi.fn(async (key: Address) =>
              key === pda.address
                ? { owner: USER_REGISTRY_PROGRAM_ID, data: record, lamports: 1n }
                : undefined,
            ),
            proveMerge: ({ prepared }) =>
              answer(() => {
                const complete = prepareMerge(prepared, TREE).finish({
                  slot: { id: 0, utxoRoot: filled(1), nullifierRoot: filled(2) },
                  utxoRootIndex: 0,
                  nullifierRootIndex: 0,
                });
                return {
                  data: complete.instructionData({
                    a: filled(0),
                    b: new Uint8Array(128) as Bytes128,
                    c: filled(0),
                  }),
                  outputHash: complete.outputHash,
                };
              }),
            assembleAuthorizedMergeTransaction: vi.fn(async () => TRANSACTION),
          },
          wallet,
          keys,
          feePayer: owner,
        },
        context,
      ).catch((cause: unknown) => cause);
      return { result, calls, wallet };
    } finally {
      keys.destroy();
    }
  }

  const failure = (kind: "transfer" | "merge") => ({
    code: kind === "transfer" ? "WALLET_BUILD_TRANSFER" : "WALLET_BUILD_MERGE",
    causeCode: "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
  });

  it.each(["transfer", "merge"] as const)(
    "retries a %s once the prover's indexer catches up",
    async (kind) => {
      const { result, calls } = await build(kind, "prover", 1);
      expect(result).toBe(TRANSACTION);
      expect(calls).toBe(2);
    },
  );

  it.each(["transfer", "merge"] as const)(
    "fails a %s at once on the client source and releases its inputs",
    async (kind) => {
      const { result, calls, wallet } = await build(kind, "client", 1);
      expect(result).toMatchObject(failure(kind));
      expect(calls).toBe(1);
      expect(wallet._reservationEntries()).toHaveLength(0);
    },
  );

  it.each(["transfer", "merge"] as const)(
    "releases a %s's inputs once the retries run out",
    async (kind) => {
      const { result, calls, wallet } = await build(kind, "prover", Infinity, {
        timeoutMs: 1_000,
      });
      expect(result).toMatchObject(failure(kind));
      expect(calls).toBeGreaterThan(1);
      expect(wallet._reservationEntries()).toHaveLength(0);
    },
  );
});

describe("keys at the wallet boundary", () => {
  it("refuses a merge whose key holder answers the derivation batch short", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n]);
    const local = LocalShieldedKeys.fromKeypair(keypair);
    const short: ShieldedKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: async (requests) => (await local.derive(requests)).slice(1),
      transactionKeys: (requests) => local.transactionKeys(requests),
    };
    await expect(createMerge({ wallet, keys: short, asset: SOL_MINT })).rejects.toMatchObject({
      code: "WALLET_KEYS_BATCH_MISMATCH",
    });
    // The refused merge holds nothing.
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it.each(["null", "object", "string", "short bytes", "hole"])(
    "reports a merge holder's %s answer through the public builder and releases its reservation",
    async (shape) => {
      const keypair = ShieldedKeypair.generate();
      const wallet = fundedWallet(keypair, [20n, 30n]);
      const keys = localKeys(keypair);
      const before = serializeWallet(wallet);
      const derive = keys.derive.bind(keys);
      // Exercise malformed JavaScript implementations without asserting a fake type.
      Object.defineProperty(keys, "derive", {
        value: async (requests: Parameters<typeof derive>[0]) => {
          const answers: unknown[] = [...(await derive(requests))];
          if (shape === "null") return null;
          if (shape === "object") return {};
          if (shape === "hole") delete answers[2];
          else answers[2] = shape === "string" ? "invalid" : new Uint8Array(16);
          return answers;
        },
      });
      const unexpected = vi.fn((): never => {
        throw new Error("malformed derivations must fail before reaching the client");
      });
      const client: MergeClient = {
        proofDataSource: "client",
        tree: TREE,
        treeId: 0,
        getAccount: unexpected,
        proveMerge: unexpected,
        assembleAuthorizedMergeTransaction: unexpected,
      };
      try {
        await expect(
          buildMergeTransaction({ client, wallet, keys, asset: SOL_MINT, feePayer: PAYER }),
        ).rejects.toMatchObject({
          code: "WALLET_BUILD_MERGE",
          causeCode: "WALLET_KEYS_BATCH_MISMATCH",
        });
        expect(wallet._reservationEntries()).toHaveLength(0);
        expect(serializeWallet(wallet)).toBe(before);
        expect(unexpected).not.toHaveBeenCalled();
      } finally {
        keys.destroy();
        keypair.destroy();
      }
    },
  );

  it("refuses non-default tree entries before deriving merge material", async () => {
    const owner = ShieldedKeypair.generate();
    const wallet = fundedWallet(owner, [20n, 30n]);
    const keys = localKeys(owner);
    const utxos = wallet.utxos().map((entry) => ({
      ...entry,
      outputContext: { ...entry.outputContext, tree: treeAddress(1) },
    }));
    wallet._replace({ utxos, transactions: [], nullifiers: new Set() });
    const before = serializeWallet(wallet);
    const derive = vi.spyOn(keys, "derive");
    try {
      for (const entry of wallet.utxos()) {
        expect(() => proofInputFromEntry(entry, owner.shieldedAddress())).toThrow(
          expect.objectContaining({ code: "WALLET_INPUT_UTXO_TREE_MISMATCH" }),
        );
      }
      await expect(createMerge({ wallet, keys, asset: SOL_MINT })).rejects.toMatchObject({
        code: "WALLET_INPUT_UTXO_TREE_MISMATCH",
      });
      expect(derive).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
      expect(serializeWallet(wallet)).toBe(before);
    } finally {
      keys.destroy();
      owner.destroy();
    }
  });

  it("refuses keys without a prover before copying any secret", () => {
    const keypair = ShieldedKeypair.generate();
    const minted: NullifierKey[] = [];
    const nullifier = keypair.nullifierKey.bind(keypair);
    vi.spyOn(keypair, "nullifierKey").mockImplementation(() => {
      const key = nullifier();
      minted.push(key);
      return key;
    });
    expect(() =>
      Reflect.apply(LocalKeys.fromKeypair, LocalKeys, [keypair, { prove: "later" }]),
    ).toThrowError(expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }));
    expect(minted).toHaveLength(0);
  });
});

describe("unsigned public transaction builders", () => {
  it("builds a normal unsigned deposit that consumers sign with Kit", async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildDepositTransaction({
      client: latestBlockhashClient(),
      feePayer: signer.address,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 42n,
    });

    expect(() => assertIsFullySignedTransaction(transaction)).toThrow();
    const signed = await signTransactionWithSigners([signer], transaction);
    expect(() => assertIsFullySignedTransaction(signed)).not.toThrow();
  });

  it("tags a deposit with the recipient confidential view tag", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const deposit = await createDeposit({
      recipient,
      asset: SOL_MINT,
      amount: 42n,
    });
    expect(deposit.viewTag()).toEqual(recipient.confidentialViewTag());
  });

  it("threads Token-2022 through an SPL deposit", async () => {
    const deposit = await createDeposit({
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      asset: SPL_MINT,
      amount: 42n,
      splTokenAccount: RECIPIENT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    const instruction = await deposit.instruction(TREE, PAYER);
    expect(
      instruction.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("includes idempotent Token-2022 ATA setup in a withdrawal build", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n], { asset: SPL_MINT });
    const { client, assemble } = capturePrivateBuild();

    await buildWithdrawalTransaction({
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
      recipient: RECIPIENT,
      asset: SPL_MINT,
      amount: 25n,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });

    const request = assemble.mock.calls[0]?.[0];
    if (request === undefined) throw new Error("assembly request was not captured");
    const material = authorizedPrivateTransactionMaterial(request.authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.setupInstructions).toHaveLength(1);
    expect(
      material.setupInstructions[0]?.accounts?.some(
        (account) => account.address === SPL_TOKEN_2022_PROGRAM_ID,
      ),
    ).toBe(true);
    expect(material.withdrawal).toMatchObject({
      kind: "spl",
      tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
  });

  it("builds a transfer and a split whose fee payer sponsors the UTXO owner", async () => {
    const keypair = spendingKeypair();
    const owner = keypair.shieldedAddress().solanaAddress();
    const { client, assemble } = capturePrivateBuild();

    await buildTransferTransaction({
      client,
      wallet: fundedWallet(keypair, [100n]),
      keys: localKeys(keypair),
      feePayer: RECIPIENT,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    });
    await buildSplitTransaction({
      client,
      wallet: fundedWallet(keypair, [100n]),
      keys: localKeys(keypair),
      feePayer: RECIPIENT,
    });

    expect(assemble).toHaveBeenCalledTimes(2);
    for (const [request] of assemble.mock.calls) {
      expect(request.feePayer).toBe(RECIPIENT);
      const material = authorizedPrivateTransactionMaterial(request.authorized);
      if (material === undefined) throw new Error("authorization was not minted");
      expect(material.proofInputs.payer).toBe(RECIPIENT);
      expect(
        ownerSignerAddresses(material.proofInputs.inputUtxos, material.proofInputs.outputs),
      ).toEqual([owner]);
    }
  });

  it("hands the build's request context to the key holder", async () => {
    // A remote holder stops its round trip when the caller's signal fires;
    // that only works if the build passes the context it was given on.
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [20n, 30n, 100n]);
    const local = LocalShieldedKeys.fromKeypair(keypair);
    const seen: unknown[] = [];
    const keys: ShieldedKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: (requests, context) => {
        seen.push(context);
        return local.derive(requests);
      },
      transactionKeys: (requests, context) => {
        seen.push(context);
        return local.transactionKeys(requests);
      },
    };
    const context = { signal: new AbortController().signal, timeoutMs: 1_000 };
    const { client } = capturePrivateBuild();

    await buildTransferTransaction(
      {
        client,
        wallet,
        keys: { ...keys, ...stubProofs() },
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 25n,
      },
      context,
    );
    await createMerge({ wallet, keys, asset: SOL_MINT }, context);

    expect(seen).toHaveLength(2);
    expect(seen.every((entry) => entry === context)).toBe(true);
  });

  it("does not mutate spend state and holds the UTXOs after a build", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const input = {
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    } as const;

    await buildTransferTransaction(input);
    await expect(buildTransferTransaction(input)).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"],
    });

    expect(assemble).toHaveBeenCalledTimes(1);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
    expect(wallet.utxos()[0]?.spent).toBe(false);
  });

  it.each(["single", "multi"] as const)(
    "checks a service recipient again after assembling a %s transfer and releases inputs on failure",
    async (kind) => {
      const keypair = spendingKeypair();
      const wallet = fundedWallet(keypair, [100n]);
      const recipient = ShieldedKeypair.generate().shieldedAddress();
      const replacement = ShieldedKeypair.generate().shieldedAddress();
      const changed = ShieldedAddress.fromPublicKeys(
        recipient.signingPublicKey,
        replacement.nullifierPublicKey,
        replacement.viewingPublicKey,
      );
      const { client, assemble } = capturePrivateBuild();
      const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
      const address = vi
        .fn(async () => recipient)
        .mockResolvedValueOnce(recipient)
        .mockResolvedValueOnce(changed);
      const input = {
        client: { ...client, getGenesisHash: async () => genesisHash },
        wallet,
        keys: localKeys(keypair),
        feePayer: keypair.shieldedAddress().solanaAddress(),
        decryptionService: { address, genesisHash },
      };
      const payment = { recipient: recipient.solanaAddress(), amount: 25n };
      const build = () =>
        kind === "single"
          ? buildTransferTransaction({ ...input, ...payment })
          : buildMultiTransferTransaction({ ...input, payments: [payment, payment] });
      await expect(build()).rejects.toMatchObject({
        causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
      });
      expect(assemble).toHaveBeenCalledOnce();
      expect(address).toHaveBeenCalledTimes(2);
      await expect(build()).resolves.toBeDefined();
    },
  );

  it("releases reserved inputs when a service recipient registers different keys during proving", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const owner = recipient.solanaAddress();
    const registered = ShieldedKeypair.generate().shieldedAddress();
    const pda = await internalUserRecordPda(owner);
    const record = {
      owner: USER_REGISTRY_PROGRAM_ID,
      lamports: 1n,
      data: Uint8Array.of(
        1,
        ...getAddressEncoder().encode(owner),
        pda.bump,
        ...registered.nullifierPublicKey,
        ...registered.viewingPublicKey.toBytes(),
        0,
      ),
    };
    const { client, assemble } = capturePrivateBuild();
    const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const address = vi.fn(async () => recipient);
    const before = serializeWallet(wallet);
    await expect(
      buildTransferTransaction({
        client: {
          ...client,
          ...registryReads(async () => (assemble.mock.calls.length > 0 ? record : undefined)),
          getGenesisHash: async () => genesisHash,
        },
        wallet,
        keys: localKeys(keypair),
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: owner,
        amount: 25n,
        decryptionService: { address, genesisHash },
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
    });
    expect(assemble).toHaveBeenCalledOnce();
    expect(address).toHaveBeenCalledOnce();
    expect(serializeWallet(wallet)).toEqual(before);
  });

  it.each([
    "recipient changed",
    "registry changed",
    "broadcast uncertain",
    "cancelled",
    "expired before signing",
  ] as const)(
    "keeps spend reservations consistent when a prepared payment is %s",
    async (outcome) => {
      const keypair = spendingKeypair();
      const payer = await generateKeyPairSigner();
      const wallet = fundedWallet(keypair, [100n]);
      const recipient = ShieldedKeypair.generate().shieldedAddress();
      const replacement = ShieldedKeypair.generate().shieldedAddress();
      const changed = ShieldedAddress.fromPublicKeys(
        recipient.signingPublicKey,
        replacement.nullifierPublicKey,
        replacement.viewingPublicKey,
      );
      const { client } = capturePrivateBuild(emptyTransaction(payer.address));
      const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
      let approved = false;
      const owner = recipient.solanaAddress();
      const pda = await internalUserRecordPda(owner);
      const getAccount = async () =>
        outcome === "registry changed"
          ? {
              owner: USER_REGISTRY_PROGRAM_ID,
              lamports: 1n,
              data: Uint8Array.of(
                1,
                ...getAddressEncoder().encode(owner),
                pda.bump,
                ...recipient.nullifierPublicKey,
                ...(approved ? changed : recipient).viewingPublicKey.toBytes(),
                0,
              ),
            }
          : undefined;
      const address = vi.fn(async () =>
        approved && outcome === "recipient changed" ? changed : recipient,
      );
      const broadcastTransaction = vi.fn(async () => {
        throw new ClientError("CLIENT_RPC", { details: { method: "sendTransaction" } });
      });
      const before = serializeWallet(wallet);
      const payment = await buildTransferTransaction({
        client: {
          ...client,
          ...registryReads(getAccount),
          getGenesisHash: async () => genesisHash,
          getBlockhashValidity: async () => ({
            slot: 1n,
            valid: outcome !== "expired before signing",
          }),
          broadcastTransaction,
        },
        wallet,
        keys: localKeys(keypair),
        feePayer: payer.address,
        recipient: owner,
        amount: 25n,
        decryptionService: { address, genesisHash },
      });
      const sign = vi.fn(async (transaction: Transaction) => {
        approved = true;
        return signTransactionWithSigners([payer], transaction);
      });
      expect(serializeWallet(wallet)).not.toEqual(before);
      if (outcome === "cancelled") payment.cancel();
      const causeCode =
        outcome === "cancelled"
          ? "WALLET_PAYMENT_ALREADY_USED"
          : outcome === "expired before signing"
            ? "WALLET_PAYMENT_BLOCKHASH"
            : outcome === "recipient changed" || outcome === "registry changed"
              ? "WALLET_DECRYPTION_RECIPIENT_MISMATCH"
              : "CLIENT_RPC";
      await expect(payment.send(sign)).rejects.toMatchObject({
        code: "WALLET_SUBMIT_PAYMENT",
        causeCode,
      });
      payment.cancel();
      expect(sign).toHaveBeenCalledTimes(
        outcome === "cancelled" || outcome === "expired before signing" ? 0 : 1,
      );
      expect(broadcastTransaction).toHaveBeenCalledTimes(outcome === "broadcast uncertain" ? 1 : 0);
      if (outcome === "registry changed") expect(address).not.toHaveBeenCalled();
      if (outcome === "broadcast uncertain") {
        expect(serializeWallet(wallet)).not.toEqual(before);
        const restored = deserializeWallet(serializeWallet(wallet));
        expect(restored.pendingSubmissions()).toMatchObject([
          {
            genesisHash,
            lastValidBlockHeight: 1n,
            attempts: 1,
          },
        ]);
        expect(restored._activeReservations(BigInt(Date.now()) + 120_000n)).toHaveLength(1);
        await expect(payment.send(sign)).rejects.toMatchObject({
          causeCode: "WALLET_PAYMENT_ALREADY_USED",
        });
      } else {
        expect(serializeWallet(wallet)).toEqual(before);
      }
    },
  );

  it.each([
    "saved",
    "uncertain send",
    "save failed",
    "recipient changed",
    "recipient changed during the blockhash check",
    "blockhash expired",
    "RPC slot regressed",
    "input spent",
    "aborted",
  ] as const)("guards RPC broadcast when payment persistence is %s", async (outcome) => {
    const keypair = spendingKeypair();
    const payer = await generateKeyPairSigner();
    const wallet = fundedWallet(keypair, [100n]);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const rotated = ShieldedAddress.fromPublicKeys(
      recipient.signingPublicKey,
      recipient.nullifierPublicKey,
      ShieldedKeypair.generate().shieldedAddress().viewingPublicKey,
    );
    const { client } = capturePrivateBuild(emptyTransaction(payer.address));
    const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const before = serializeWallet(wallet);
    const controller = new AbortController();
    let stored: string | undefined;
    let finishSave = () => {};
    const writing = new Promise<void>((resolve) => {
      finishSave = resolve;
    });
    const cipher = walletSnapshotCipher(keypair);
    const store = {
      load: async () => stored,
      save: vi.fn(async (sealed: string, context?: RequestContext) => {
        expect(context?.signal).toBeDefined();
        await writing;
        if (outcome === "save failed") throw new Error("store write failed");
        stored = sealed;
      }),
    };
    const address = vi.fn(async () => {
      if (
        (outcome === "recipient changed" ||
          outcome === "recipient changed during the blockhash check") &&
        stored !== undefined
      ) {
        return rotated;
      }
      return recipient;
    });
    const getBlockhashValidity = vi.fn(async () => {
      if (stored === undefined) return { slot: 10n, valid: true };
      return {
        slot: outcome === "RPC slot regressed" ? 9n : 11n,
        valid: outcome !== "blockhash expired",
      };
    });
    const broadcastTransaction = vi.fn(async (transaction: Transaction) => {
      const signature = getSignatureFromTransaction(transaction);
      const restored = await loadPersistedWallet({ store, cipher });
      expect(restored?.pendingSubmissions()).toMatchObject([
        { signature, genesisHash, lastValidBlockHeight: 1n, blockhashValidAtSlot: 10n },
      ]);
      expect(restored?._activeReservations(BigInt(Date.now()) + 120_000n)).toHaveLength(1);
      if (outcome === "uncertain send") {
        throw new ClientError("CLIENT_RPC", { details: { method: "sendTransaction" } });
      }
      return signature;
    });
    const persistence = { store, cipher, wallet: fundedWallet(keypair, []) };
    const payment = await buildTransferTransaction({
      client: {
        ...client,
        getBlockhashValidity,
        broadcastTransaction,
        getGenesisHash: async () => genesisHash,
      },
      wallet,
      keys: localKeys(keypair),
      feePayer: payer.address,
      recipient: recipient.solanaAddress(),
      amount: 25n,
      decryptionService: { address, genesisHash },
      persistence,
    });
    const sending = payment.send(
      (transaction) => signTransactionWithSigners([payer], transaction),
      { signal: controller.signal },
    );
    const failure = {
      "uncertain send": "CLIENT_RPC",
      "save failed": "WALLET_PERSIST",
      "recipient changed": "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
      "recipient changed during the blockhash check": "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
      "blockhash expired": "WALLET_PAYMENT_BLOCKHASH",
      "RPC slot regressed": "WALLET_PAYMENT_BLOCKHASH",
      "input spent": "WALLET_UNSIGNED_INPUT_UNAVAILABLE",
      aborted: "CLIENT_ABORTED",
    };
    const settled =
      outcome === "saved"
        ? expect(sending).resolves.toEqual(expect.any(String))
        : expect(sending).rejects.toMatchObject({
            code: "WALLET_SUBMIT_PAYMENT",
            causeCode: failure[outcome],
          });
    try {
      await vi.waitFor(() => expect(store.save).toHaveBeenCalledOnce());
      expect(broadcastTransaction).not.toHaveBeenCalled();
      expect(getBlockhashValidity).toHaveBeenCalledTimes(2);
      expect(wallet.pendingSubmissions()).toHaveLength(1);
      if (outcome === "input spent") {
        wallet._replace({
          ...wallet._state(),
          utxos: wallet.utxos().map((entry) => ({ ...entry, spent: true })),
        });
      }
      if (outcome === "aborted") {
        controller.abort();
        await settled;
        expect(broadcastTransaction).not.toHaveBeenCalled();
      }
    } finally {
      finishSave();
    }
    await settled;
    await wallet._withSyncLock(async () => {});
    const attempted = outcome === "saved" || outcome === "uncertain send";
    expect(broadcastTransaction).toHaveBeenCalledTimes(attempted ? 1 : 0);
    if (attempted) {
      expect(wallet.pendingSubmissions()).toHaveLength(1);
    } else {
      expect(wallet.pendingSubmissions()).toEqual([]);
      if (outcome !== "input spent") expect(serializeWallet(wallet)).toBe(before);
    }
    if (outcome === "aborted") {
      const restored = await loadPersistedWallet({ store, cipher });
      expect(restored?.pendingSubmissions()).toEqual([]);
    }
  });

  it("cannot stage or broadcast a cancelled payment waiting behind the wallet save queue", async () => {
    const keypair = spendingKeypair();
    const payer = await generateKeyPairSigner();
    const wallet = fundedWallet(keypair, [100n]);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const { client } = capturePrivateBuild(emptyTransaction(payer.address));
    const genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const store = { save: vi.fn(async () => {}) };
    const broadcastTransaction = vi.fn(async (transaction: Transaction) =>
      getSignatureFromTransaction(transaction),
    );
    const payment = await buildTransferTransaction({
      client: { ...client, broadcastTransaction, getGenesisHash: async () => genesisHash },
      wallet,
      keys: localKeys(keypair),
      feePayer: payer.address,
      recipient: recipient.solanaAddress(),
      amount: 25n,
      decryptionService: { address: async () => recipient, genesisHash },
      persistence: { store, cipher: walletSnapshotCipher(keypair) },
    });
    let finish = () => {};
    const blocking = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const currentWriter = wallet._withSyncLock(() => blocking);
    const stage = vi.spyOn(wallet, "_beginSubmission");
    const sign = vi.fn(async (transaction: Transaction) =>
      signTransactionWithSigners([payer], transaction),
    );
    const controller = new AbortController();
    const sending = expect(payment.send(sign, { signal: controller.signal })).rejects.toMatchObject(
      {
        code: "WALLET_SUBMIT_PAYMENT",
        causeCode: "CLIENT_ABORTED",
      },
    );
    try {
      await vi.waitFor(() => expect(sign).toHaveBeenCalledOnce());
      expect(stage).not.toHaveBeenCalled();
      controller.abort();
      await sending;
    } finally {
      finish();
    }
    await currentWriter;
    await wallet._withSyncLock(async () => {});
    expect(stage).not.toHaveBeenCalled();
    expect(store.save).not.toHaveBeenCalled();
    expect(broadcastTransaction).not.toHaveBeenCalled();
    expect(wallet.pendingSubmissions()).toEqual([]);
    expect(wallet._activeReservations(BigInt(Date.now()))).toEqual([]);
  });

  it("applies split defaults without mutating the wallet", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();

    await buildSplitTransaction({
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
    });

    const authorized = (assemble.mock.calls[0]![0] as { authorized: AuthorizedPrivateTransaction })
      .authorized;
    const material = authorizedPrivateTransactionMaterial(authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.proofInputs.outputs.filter((output) => output.amount > 0n)).toHaveLength(2);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
  });
});

describe("resolveWithdrawal", () => {
  it("uses one idempotent ATA setup policy for every withdrawal rail", async () => {
    await expect(
      withdrawalSetupInstructions({ payer: PAYER, recipient: RECIPIENT, asset: SOL_MINT }),
    ).resolves.toEqual([]);
    const setup = await withdrawalSetupInstructions({
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SPL_MINT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    expect(setup).toHaveLength(1);
    expect(
      setup[0]?.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("derives one SPL settlement, shared by the proof side and the accounts side", async () => {
    const resolved = await resolveWithdrawal(RECIPIENT, SPL_MINT, SPL_TOKEN_2022_PROGRAM_ID);
    if (resolved.target.kind !== "spl" || resolved.accounts.kind !== "spl") {
      throw new Error("an SPL mint resolves to SPL settlement");
    }
    expect(resolved.accounts.recipientTokenAccount).toBe(resolved.target.recipientTokenAccount);
    expect(resolved.accounts.splTokenInterface).toBe(resolved.target.splTokenInterface);
    expect(resolved.accounts.mint).toBe(SPL_MINT);
    expect(resolved.accounts.tokenProgram).toBe(SPL_TOKEN_2022_PROGRAM_ID);
    expect(resolved.target.recipientTokenAccount).toBe(
      await associatedTokenAddress(RECIPIENT, SPL_MINT, SPL_TOKEN_2022_PROGRAM_ID),
    );
    const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(SPL_MINT);
    expect(resolved.target.splTokenInterface).toBe(splTokenInterface);
    expect(resolved.target.splInterfaceBump).toBe(splInterfaceBump);
  });

  it("settles SOL through the recipient account itself", async () => {
    const resolved = await resolveWithdrawal(RECIPIENT, SOL_MINT);
    if (resolved.target.kind !== "sol" || resolved.accounts.kind !== "sol") {
      throw new Error("SOL resolves to SOL settlement");
    }
    expect(resolved.target.recipient).toBe(RECIPIENT);
    expect(resolved.accounts.recipient).toBe(RECIPIENT);
  });
});

describe("wallet balances split", () => {
  function mixedWallet(keypair: ShieldedKeypair): Wallet {
    const wallet = fundedWallet(keypair, [10n]);
    const entry = (index: number, amount: bigint, ringProgramId?: Address) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: { hash: filled(index + 1), tree: TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    });
    wallet._replace({
      utxos: [entry(0, 10n), entry(1, 40n, RING), entry(2, 60n, RECIPIENT)],
      transactions: [],
      nullifiers: new Set(),
    });
    return wallet;
  }

  it("keeps ring-bound UTXOs out of the spendable view like Rust `balances`", () => {
    const wallet = mixedWallet(spendingKeypair());
    const spendable = wallet.balances(true);
    expect(spendable.map((balance) => balance.amount)).toEqual([10n]);
    expect(wallet.balance(SOL_MINT).amount).toBe(10n);
  });

  it("groups ring-bound UTXOs by ring in address order", () => {
    const wallet = mixedWallet(spendingKeypair());
    const rings = wallet.ringBalances(true);
    const expected = [[RING, 40n] as const, [RECIPIENT, 60n] as const].sort(([left], [right]) =>
      left < right ? -1 : 1,
    );
    expect(rings.map((ring) => [ring.ringProgramId, ring.assets[0]?.amount])).toEqual(expected);
  });
});

describe("AssetRegistry register", () => {
  it("inserts once, skips the exact pair, and raises on a conflicting binding", () => {
    const registry = new AssetRegistry();
    expect(registry.register(2n, SPL_MINT)).toBe(true);
    expect(registry.register(2n, SPL_MINT)).toBe(false);
    expect(() => registry.register(2n, RECIPIENT)).toThrow("TRANSACTION_DUPLICATE_ASSET_ID");
    expect(() => registry.register(3n, SPL_MINT)).toThrow("TRANSACTION_DUPLICATE_MINT");
  });
});

describe("key lifecycle", () => {
  it("wipes the per-transaction key once the build succeeds and never lends the nullifier key", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const keys = localKeys(keypair);
    const minted = captureTransactionKeys(keys);

    await buildTransferTransaction({
      client,
      wallet,
      keys,
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    });

    const authorized = (assemble.mock.calls[0]![0] as { authorized: AuthorizedPrivateTransaction })
      .authorized;
    const material = authorizedPrivateTransactionMaterial(authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    // Proof inputs carry the nullifier public key and the nullifier, never the secret.
    const real = material.proofInputs.inputUtxos.filter((proofInput) => !proofInput.isDummy());
    expect(real).toHaveLength(1);
    for (const proofInput of real) {
      expect(Object.keys(proofInput)).not.toContain("nullifierKey");
      expect(proofInput.nullifierPublicKey).toEqual(keypair.nullifierPublicKey());
    }
    expect(minted).toHaveLength(1);
    expect(() => minted[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });

  it("wipes the per-transaction key and releases the inputs when approval fails", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const keys = localKeys(keypair);
    const minted = captureTransactionKeys(keys);
    const input = {
      client,
      wallet,
      keys,
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    } as const;

    await expect(
      buildTransferTransaction({ ...input, approve: () => Promise.reject(new Error("refused")) }),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    expect(assemble).not.toHaveBeenCalled();
    expect(minted).toHaveLength(1);
    expect(() => minted[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    // The refused build holds nothing: the same UTXO funds the next one.
    await buildTransferTransaction(input);
    expect(assemble).toHaveBeenCalledTimes(1);
  });

  it("decryptToBalances wipes its minted keys", async () => {
    const keypair = ShieldedKeypair.generate();
    const mintedViewing: ReturnType<ShieldedKeypair["viewingKey"]>[] = [];
    const mintedNullifier: NullifierKey[] = [];
    const viewing = keypair.viewingKey.bind(keypair);
    const nullifier = keypair.nullifierKey.bind(keypair);
    vi.spyOn(keypair, "viewingKey").mockImplementation(() => {
      const key = viewing();
      mintedViewing.push(key);
      return key;
    });
    vi.spyOn(keypair, "nullifierKey").mockImplementation(() => {
      const key = nullifier();
      mintedNullifier.push(key);
      return key;
    });

    await decryptToBalances({ keypair, registry: new AssetRegistry(), transactions: [] });

    expect(mintedViewing).toHaveLength(1);
    expect(mintedNullifier).toHaveLength(1);
    expect(() => mintedViewing[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    expect(() => mintedNullifier[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });
});

describe("multi-recipient transfer", () => {
  function build(
    wallet: Wallet,
    keypair: ShieldedKeypair,
    payments: readonly Readonly<{ recipient: ShieldedAddress | Address; amount: bigint }>[],
    approve?: (request: ApprovalRequest) => Promise<ReturnType<typeof approveIntent>>,
  ) {
    const { client, assemble } = capturePrivateBuild();
    return {
      assemble,
      result: buildMultiTransferTransaction({
        client,
        wallet,
        keys: localKeys(keypair),
        feePayer: keypair.shieldedAddress().solanaAddress(),
        payments,
        ...(approve === undefined ? {} : { approve }),
      }),
    };
  }

  it("pays several recipients in one transaction and asks approval for each payment", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const merchant = ShieldedKeypair.generate().shieldedAddress();
    const fee = ShieldedKeypair.generate().shieldedAddress();
    const { approve, requests } = recordingApproval();
    const { result, assemble } = build(
      wallet,
      keypair,
      [
        { recipient: merchant, amount: 25n },
        { recipient: fee, amount: 1n },
      ],
      approve,
    );
    await expect(result).resolves.toBe(TRANSACTION);
    expect(assemble).toHaveBeenCalledOnce();
    expect(requests).toHaveLength(1);
    expect(requests[0]?.intent).toEqual({
      kind: "multiTransfer",
      asset: SOL_MINT,
      payments: [
        { recipient: merchant, amount: 25n },
        { recipient: fee, amount: 1n },
      ],
    });
    expect(requests[0]?.summary).toBe("private transaction transfer of 26 to 2 recipients");
    expect(wallet.utxos()[0]?.spent).toBe(false);
  });

  it("lets a fee payer other than the owner sponsor the payments", async () => {
    const keypair = spendingKeypair();
    const owner = keypair.shieldedAddress().solanaAddress();
    const { client, assemble } = capturePrivateBuild();
    await buildMultiTransferTransaction({
      client,
      wallet: fundedWallet(keypair, [100n]),
      keys: localKeys(keypair),
      feePayer: RECIPIENT,
      payments: [
        { recipient: ShieldedKeypair.generate().shieldedAddress(), amount: 25n },
        { recipient: ShieldedKeypair.generate().shieldedAddress(), amount: 1n },
      ],
    });
    const [request] = assemble.mock.calls[0]!;
    expect(request.feePayer).toBe(RECIPIENT);
    const material = authorizedPrivateTransactionMaterial(request.authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.proofInputs.payer).toBe(RECIPIENT);
    expect(
      ownerSignerAddresses(material.proofInputs.inputUtxos, material.proofInputs.outputs),
    ).toEqual([owner]);
  });

  it("keeps a single payment a transfer approval", async () => {
    const keypair = spendingKeypair();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const { approve, requests } = recordingApproval();
    await build(fundedWallet(keypair, [100n]), keypair, [{ recipient, amount: 25n }], approve)
      .result;
    expect(requests[0]?.intent).toEqual({
      kind: "transfer",
      asset: SOL_MINT,
      amount: 25n,
      recipient,
    });
  });

  it("refuses empty, oversized and zero-value payment lists without reserving UTXOs", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    await expect(build(wallet, keypair, []).result).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INVALID_PAYMENT_COUNT"],
    });
    await expect(
      createMultiTransfer({
        wallet,
        payer: PAYER,
        asset: SOL_MINT,
        payments: Array.from({ length: 16 }, () => ({ recipient, amount: 1n })),
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INVALID_PAYMENT_COUNT",
    });
    await expect(
      build(wallet, keypair, [
        { recipient, amount: 10n },
        { recipient, amount: 0n },
      ]).result,
    ).rejects.toMatchObject({
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INVALID_AMOUNT"],
    });
    await expect(
      build(wallet, keypair, [
        { recipient, amount: 1n << 63n },
        { recipient, amount: 1n << 63n },
      ]).result,
    ).rejects.toMatchObject({
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INVALID_AMOUNT"],
    });
    // Nothing above reserved the UTXO, so the whole balance is still spendable.
    await expect(
      build(wallet, keypair, [
        { recipient, amount: 60n },
        { recipient, amount: 40n },
      ]).result,
    ).resolves.toBe(TRANSACTION);
  });

  it("refuses an unregistered recipient before reserving UTXOs", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const getAccount = vi.fn(async () => undefined);
    await expect(
      createMultiTransfer({
        client: { getAccount },
        wallet,
        payer: PAYER,
        asset: SOL_MINT,
        payments: [
          { recipient: ShieldedKeypair.generate().shieldedAddress(), amount: 10n },
          { recipient: RECIPIENT, amount: 1n },
        ],
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_RECIPIENT_NOT_REGISTERED",
    });
    expect(getAccount).toHaveBeenCalledOnce();
    await expect(
      build(wallet, keypair, [
        { recipient: ShieldedKeypair.generate().shieldedAddress(), amount: 99n },
        { recipient: ShieldedKeypair.generate().shieldedAddress(), amount: 1n },
      ]).result,
    ).resolves.toBe(TRANSACTION);
  });

  it("holds a spend with change to the narrower proof and lets an exact spend use the wider one", async () => {
    const keypair = spendingKeypair();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const utxos = (count: number) =>
      fundedWallet(
        keypair,
        Array.from({ length: count }, () => 4n),
      );
    const pay = (wallet: Wallet, total: bigint) =>
      createMultiTransfer({
        wallet,
        payer: PAYER,
        asset: SOL_MINT,
        payments: [
          { recipient, amount: total - 10n },
          { recipient, amount: 10n },
        ],
      });
    // Two payments and change prove on 4-output keys, which take 24 UTXOs.
    expect((await pay(utxos(25), 95n)).transaction.inputCount()).toBe(24);
    await expect(pay(utxos(30), 97n)).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_TOO_MANY_INPUTS",
    });
    // An exact spend has no change output, so two payments prove on 2-output keys.
    expect((await pay(utxos(25), 100n)).transaction.inputCount()).toBe(25);
    // One recipient keeps the 2-output cap, so the same UTXOs still cover it.
    await expect(
      createTransfer({ wallet: utxos(25), payer: PAYER, recipient, asset: SOL_MINT, amount: 100n }),
    ).resolves.toHaveProperty("transaction");
  });
});

describe("merge encryption opt-in", () => {
  it("refuses an owner whose record disables merging before proving", async () => {
    const keypair = spendingKeypair();
    const shielded = keypair.shieldedAddress();
    const owner = shielded.solanaAddress();
    const wallet = fundedWallet(keypair, [20n, 30n]);
    const keys = localKeys(keypair);
    const pda = await internalUserRecordPda(owner);
    const record = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(owner),
      pda.bump,
      ...shielded.nullifierPublicKey,
      ...shielded.viewingPublicKey.toBytes(),
      0,
    );
    const unexpected = vi.fn((): never => {
      throw new Error("a disabled record must fail before proving");
    });
    try {
      await expect(
        buildMergeTransaction({
          client: {
            proofDataSource: "client",
            tree: TREE,
            treeId: 0,
            getAccount: vi.fn(async (key: Address) =>
              key === pda.address
                ? { owner: USER_REGISTRY_PROGRAM_ID, data: record, lamports: 1n }
                : undefined,
            ),
            proveMerge: unexpected,
            assembleAuthorizedMergeTransaction: unexpected,
          },
          wallet,
          keys,
          feePayer: owner,
        }),
      ).rejects.toMatchObject({
        code: "WALLET_BUILD_MERGE",
        causeCode: "WALLET_MERGE_ENCRYPTION_SCHEME_UNSUPPORTED",
      });
      expect(unexpected).not.toHaveBeenCalled();
    } finally {
      keys.destroy();
      keypair.destroy();
    }
  });
});
import { sha256 } from "@noble/hashes/sha2.js";
