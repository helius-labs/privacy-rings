import { isSignerRole } from "@solana/kit";

import type {
  BlockhashProvider,
  ChainReader,
  IndexedProofAuthority,
  IndexedProofInputs,
  ProofDataSourceContext,
  RingTransfers,
  TransactionAssembler,
  WalletKeys,
} from "../client/ports.js";
import { bytesField, hasIndexedMethod } from "../client/internal.js";
import { signTransactMessage } from "../client/prover/assembly.js";
import type { PreparedOwnerSignature, TransactOwnerSigner } from "../client/prover/types.js";
import { withProofDataRetry } from "../client/retry.js";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { initializePoseidon } from "../hasher/index.js";
import { equalBytes } from "../interface/bytes.js";
import {
  ConfidentialTransfer,
  createExternalData,
  SppProofInputs,
} from "../transaction/instructions/transact.js";
import { createProofOutput, ProofInputUtxo } from "../transaction/utxo.js";
import {
  approveUnattended,
  checkIntentApproval,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { compileUnsignedTransaction } from "../flows/compile.js";

import {
  createMultiTransfer,
  createSplit,
  createTransfer,
  createWithdrawal,
  selectSpendInputs,
  type TransferDestination,
} from "./actions.js";
import { WalletError, wrapWalletError } from "./error.js";
import {
  authorizePrivateTransaction,
  intentMismatch,
  proofInputFromEntry,
} from "./private-transaction.js";
import { withdrawalSetupInstructions } from "../flows/settlement.js";

export type PrivateTransactionClient = TransactionAssembler &
  Pick<ChainReader, "getAccount"> &
  ProofDataSourceContext;

export interface PrivateTransactionParams {
  readonly client: PrivateTransactionClient;
  readonly wallet: Wallet;
  /** The wallet's privacy roles, in-process (`LocalKeys`) or behind a remote holder. */
  readonly keys: WalletKeys;
  /**
   * Pays the fee. When it is not the shielded owner, the owner's Ed25519 key
   * is a required signer of the built transaction as well, unless `owner`
   * authorizes inside the proof.
   */
  readonly feePayer: Address;
  /**
   * The shielded owner signing inside the proof instead of the transaction,
   * so it does not sign the transaction; a `ShieldedKeypair` or any
   * `TransactOwnerSigner` holding the owner's Ed25519 key.
   */
  readonly owner?: TransactOwnerSigner;
  /** Approves the intent before proving; unattended when absent. */
  readonly approve?: ApprovalHandler;
}

export interface TransferTransactionParams extends PrivateTransactionParams {
  readonly recipient: TransferDestination;
  readonly asset?: Address;
  readonly amount: bigint;
}

/** One payment of a multi-recipient transfer. */
export interface TransferPayment {
  readonly recipient: TransferDestination;
  readonly amount: bigint;
}

export interface MultiTransferTransactionParams extends PrivateTransactionParams {
  /** Each paid as its own private output, in this order; one to fifteen of them. */
  readonly payments: readonly TransferPayment[];
  readonly asset?: Address;
}

export interface WithdrawalTransactionParams extends PrivateTransactionParams {
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenProgram?: Address | null;
}

export interface SplitTransactionParams extends PrivateTransactionParams {
  readonly asset?: Address;
  readonly parts?: number;
  readonly input?: Bytes32;
}

export async function buildTransferTransaction(
  input: TransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const created = await createTransfer(
      {
        client: input.client,
        wallet: input.wallet,
        payer: input.feePayer,
        recipient: input.recipient,
        asset: input.asset ?? SOL_MINT,
        amount: input.amount,
      },
      context,
    );
    return await buildAuthorizedTransaction(input, created.transaction, [], context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_TRANSFER", cause);
  }
}

/**
 * One private transfer of `asset` to several recipients, for example a payment
 * and an application fee. The proof hides every amount and recipient, and the
 * approval handler sees a `multiTransfer` intent listing the payments (a
 * `transfer` intent for a single payment). UTXOs beyond the input count the
 * wider proof allows fail with `WALLET_TOO_MANY_INPUTS`; merge first.
 */
export async function buildMultiTransferTransaction(
  input: MultiTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const created = await createMultiTransfer(
      {
        client: input.client,
        wallet: input.wallet,
        payer: input.feePayer,
        payments: input.payments,
        asset: input.asset ?? SOL_MINT,
      },
      context,
    );
    return await buildAuthorizedTransaction(input, created.transaction, [], context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_TRANSFER", cause);
  }
}

export async function buildWithdrawalTransaction(
  input: WithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const asset = input.asset ?? SOL_MINT;
    const setupInstructions = await withdrawalSetupInstructions({
      payer: input.feePayer,
      recipient: input.recipient,
      asset,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    });
    const created = await createWithdrawal({
      wallet: input.wallet,
      payer: input.feePayer,
      recipient: input.recipient,
      asset,
      amount: input.amount,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    });
    return await buildAuthorizedTransaction(input, created.transaction, setupInstructions, context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_WITHDRAWAL", cause);
  }
}

export async function buildSplitTransaction(
  input: SplitTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const created = createSplit({
      wallet: input.wallet,
      payer: input.feePayer,
      asset: input.asset ?? SOL_MINT,
      parts: input.parts ?? 2,
      ...(input.input === undefined ? {} : { input: input.input }),
    });
    return await buildAuthorizedTransaction(input, created.transaction, [], context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_SPLIT", cause);
  }
}

export interface RingPaymentTransactionParams extends Omit<PrivateTransactionParams, "client"> {
  readonly client: BlockhashProvider;
  readonly ring: RingTransfers;
  readonly recipient: ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
}

/** `defaultFunding` counts every selected unit, the change stays in the ring. */
export async function buildRingPaymentTransaction(
  input: RingPaymentTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    if (input.amount <= 0n) {
      throw new WalletError("WALLET_INVALID_AMOUNT", { details: { amount: String(input.amount) } });
    }
    await initializePoseidon();
    const asset = input.asset ?? SOL_MINT;
    const { ringProgramId } = input.ring;
    const { inputs, reservationId } = selectSpendInputs(input.wallet, asset, input.amount);
    let authorization: Promise<PreparedOwnerSignature | undefined> | undefined;
    try {
      const address = input.keys.address();
      const transfer = new ConfidentialTransfer(
        address,
        inputs.map(({ entry }) => proofInputFromEntry(entry, address)),
        input.feePayer,
      ).withRingProgramId(ringProgramId);
      const intent: TransactionIntent = {
        kind: "ringTransfer",
        ringProgramId,
        asset,
        amount: input.amount,
        recipient: input.recipient,
        boundary: "entry",
        defaultFunding: inputs.reduce((sum, { entry }) => sum + entry.utxo.amount, 0n),
      };
      const crossing = `moves ${String(intent.defaultFunding)} of default UTXOs into the ring`;
      const approval = await (input.approve ?? approveUnattended)({
        solanaPublicKey: address.solanaAddress(),
        intent,
        summary: `ring entry of ${String(input.amount)} in ring ${ringProgramId}, ${crossing}`,
      });
      checkIntentApproval(approval, intent, intentMismatch);
      const { recipient, amount, feePayer, owner } = input;
      const reserved = inputs.map(({ entry }) => entry);
      const { instruction, computeUnitLimit } = await input.ring.proveRingTransfer(
        {
          transfer,
          payment: { recipient, asset, amount },
          keys: paymentKeys(input.keys, reserved),
          feePayer,
          ...(owner === undefined ? {} : { owner: await owner.signingPublicKey() }),
          authorize: (proofInputs) => {
            if (authorization !== undefined) return Promise.reject(intentMismatch("authorization"));
            authorization = (async () => {
              const checked = checkedRingPayment(proofInputs, {
                source: address,
                recipient,
                asset,
                amount,
                ringProgramId,
                reserved,
              });
              const signed = owner && (await signTransactMessage(checked, owner));
              return (
                signed && {
                  ownerPublicKey: signed.ownerPublicKey,
                  ownerSignature: signed.ownerSignature,
                }
              );
            })();
            // A ring may leave it unawaited.
            authorization.catch(() => undefined);
            return authorization;
          },
        },
        context,
      );
      if (authorization === undefined) throw intentMismatch("authorization");
      await authorization;
      if (instruction.programAddress !== ringProgramId) throw intentMismatch("program");
      const allowed = owner === undefined ? [feePayer, address.solanaAddress()] : [feePayer];
      if (
        (instruction.accounts ?? []).some(
          ({ address: signer, role }) => isSignerRole(role) && !allowed.includes(signer),
        )
      )
        throw intentMismatch("signers");
      return compileUnsignedTransaction({
        feePayer,
        lifetime: await input.client.getLatestBlockhash(context),
        instructions: [instruction],
        computeUnitLimit,
      });
    } catch (cause) {
      const signed = await authorization?.then(
        (signature) => signature !== undefined,
        () => false,
      );
      if (signed !== true) input.wallet._releaseReservation(reservationId);
      throw cause;
    }
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_RING_PAYMENT", cause);
  }
}

/** Answers only for the reserved notes, every other key use is withheld. */
function paymentKeys(
  keys: WalletKeys,
  reserved: readonly WalletUtxo[],
): WalletKeys & Partial<IndexedProofAuthority> {
  const withheld = async (): Promise<never> => {
    throw new WalletError("WALLET_RING_KEY_WITHHELD");
  };
  const nullifiers = new Set(reserved.map((entry) => bytesField(entry.nullifier, "nullifier")));
  const spendsReserved = (
    inputs: Readonly<{
      payload: Readonly<{ inputs: readonly Readonly<{ isDummy: bigint; nullifier: bigint }>[] }>;
    }>,
  ): boolean =>
    inputs.payload.inputs.every((slot) => slot.isDummy === 1n || nullifiers.has(slot.nullifier));
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: withheld,
    derive: withheld,
    proveMerge: withheld,
    prove: (inputs, context) => (spendsReserved(inputs) ? keys.prove(inputs, context) : withheld()),
    transactionKeys: (requests, context) =>
      requests.every(({ firstNullifier }) =>
        reserved.some((entry) => equalBytes(entry.nullifier, firstNullifier)),
      )
        ? keys.transactionKeys(requests, context)
        : withheld(),
    ...(hasIndexedMethod(keys)
      ? {
          proveIndexed: (inputs: IndexedProofInputs, context?: RequestContext) =>
            inputs.circuit !== "merge" && spendsReserved(inputs)
              ? keys.proveIndexed(inputs, context)
              : withheld(),
        }
      : {}),
  };
}

/** Rebuilt from the notes and addresses core holds, so the digest it signs is the payment it checked. */
function checkedRingPayment(
  proofInputs: SppProofInputs,
  terms: Readonly<{
    source: ShieldedAddress;
    recipient: ShieldedAddress;
    asset: Address;
    amount: bigint;
    ringProgramId: Address;
    reserved: readonly WalletUtxo[];
  }>,
): SppProofInputs {
  const unspent = [...terms.reserved];
  const inputUtxos = proofInputs.inputUtxos.map((input) => {
    if (input.isDummy())
      return input.isCompact()
        ? ProofInputUtxo.compact(input.treeId)
        : ProofInputUtxo.dummy(input.utxo.blinding, input.treeId);
    const at = unspent.findIndex((entry) => equalBytes(entry.nullifier, input.nullifier()));
    const [entry] = at < 0 ? [] : unspent.splice(at, 1);
    if (entry === undefined) throw intentMismatch("inputs");
    return proofInputFromEntry(entry, terms.source);
  });
  if (unspent.length > 0) throw intentMismatch("inputs");
  const source = terms.source.toBytes();
  const recipient = terms.recipient.toBytes();
  let paid = 0n;
  const outputs = proofInputs.outputs.map((output) => {
    const owner = output.ownerAddress?.toBytes();
    if (owner === undefined) return createProofOutput({ ...output });
    if (output.ringProgramId !== terms.ringProgramId) throw intentMismatch("ringProgramId");
    if (equalBytes(owner, source))
      return createProofOutput({ ...output, ownerAddress: terms.source });
    if (!equalBytes(owner, recipient)) throw intentMismatch("recipient");
    if (output.asset !== terms.asset) throw intentMismatch("asset");
    paid += output.amount;
    return createProofOutput({ ...output, ownerAddress: terms.recipient });
  });
  if (!equalBytes(source, recipient) && paid !== terms.amount) throw intentMismatch("amount");
  const externalData = createExternalData({ ...proofInputs.externalData });
  if (externalData.interfaceTransfers.length !== 0) throw intentMismatch("settlements");
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos,
    outputs,
    externalData,
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
    cacheAccounts: proofInputs.cacheAccounts,
  });
}

async function buildAuthorizedTransaction(
  input: PrivateTransactionParams,
  transaction: Parameters<typeof authorizePrivateTransaction>[0],
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
): Promise<Transaction> {
  try {
    const authorized = await authorizePrivateTransaction(
      transaction,
      input.wallet,
      input.keys,
      setupInstructions,
      input.approve,
      context,
      input.owner !== undefined,
    );
    return await withProofDataRetry(
      input.client.proofDataSource,
      (attempt) =>
        input.client.assembleAuthorizedPrivateTransaction(
          {
            authorized,
            feePayer: input.feePayer,
            keys: input.keys,
            ...(input.owner === undefined ? {} : { owner: input.owner }),
          },
          attempt,
        ),
      context,
    );
  } catch (cause) {
    const reservationId = transaction._reservationId();
    if (reservationId !== undefined) input.wallet._releaseReservation(reservationId);
    throw cause;
  }
}

export type { TransferDestination } from "./actions.js";
