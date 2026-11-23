import { address } from "@solana/kit";
import {
  authorizedPrivateTransactionMaterial,
  type ChainReader,
  type PaymentBuildResult,
  type PaymentLookup,
  type PreparedPayment,
  type ProofDataSourceContext,
  type TransactionAssembler,
  type TransactionBroadcaster,
  type WalletKeys,
} from "../client/ports.js";
import type { TransactOwnerSigner } from "../client/prover/types.js";
import { withProofDataRetry } from "../client/retry.js";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import { intentHash, type ApprovalHandler } from "../transaction/wallet/intent.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { Wallet } from "../transaction/wallet/state.js";

import {
  createMultiTransfer,
  createSplit,
  createTransfer,
  createWithdrawal,
  type TransferDestination,
} from "./actions.js";
import { WalletError, wrapWalletError } from "./error.js";
import { prepareServicePayment } from "./payment.js";
import { saveWalletSnapshot, type WalletPersistence } from "./persisted.js";
import { authorizePrivateTransaction } from "./private-transaction.js";
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

export type TransferTransactionParams = PrivateTransactionParams &
  PaymentLookup<PrivateTransactionClient, Omit<WalletPersistence, "wallet">> & {
    readonly recipient: TransferDestination;
    readonly asset?: Address;
    readonly amount: bigint;
  };

/** One payment of a multi-recipient transfer. */
export interface TransferPayment {
  readonly recipient: TransferDestination;
  readonly amount: bigint;
}

export type MultiTransferTransactionParams = PrivateTransactionParams &
  PaymentLookup<PrivateTransactionClient, Omit<WalletPersistence, "wallet">> & {
    /** Each paid as its own private output, in this order; one to fifteen of them. */
    readonly payments: readonly TransferPayment[];
    readonly asset?: Address;
  };

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

export function buildTransferTransaction<Input extends TransferTransactionParams>(
  input: Input,
  context?: RequestContext,
): Promise<PaymentBuildResult<Input>>;
export async function buildTransferTransaction(
  parameters: TransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction | PreparedPayment> {
  try {
    const input = { ...parameters };
    const payment = servicePaymentOptions(input);
    const created = await createTransfer(
      {
        ...input,
        payer: input.feePayer,
        asset: input.asset ?? SOL_MINT,
      },
      context,
    );
    return await buildAuthorizedTransaction(
      input,
      created.transaction,
      [],
      context,
      payment && {
        ...payment,
        revalidate: created.revalidateRecipients,
        assertions: created.recipientAssertions,
      },
    );
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
export function buildMultiTransferTransaction<Input extends MultiTransferTransactionParams>(
  input: Input,
  context?: RequestContext,
): Promise<PaymentBuildResult<Input>>;
export async function buildMultiTransferTransaction(
  parameters: MultiTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction | PreparedPayment> {
  try {
    const input = { ...parameters };
    const payment = servicePaymentOptions(input);
    const created = await createMultiTransfer(
      {
        ...input,
        payer: input.feePayer,
        asset: input.asset ?? SOL_MINT,
      },
      context,
    );
    return await buildAuthorizedTransaction(
      input,
      created.transaction,
      [],
      context,
      payment && {
        ...payment,
        revalidate: created.revalidateRecipients,
        assertions: created.recipientAssertions,
      },
    );
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

type PaymentChecks = Readonly<{
  client: TransactionBroadcaster;
  genesisHash: string;
  persistence: WalletPersistence | undefined;
  assertions: readonly Instruction[];
  revalidate(context?: RequestContext, minContextSlot?: bigint): Promise<bigint>;
}>;

function servicePaymentOptions(
  input: TransferTransactionParams | MultiTransferTransactionParams,
): Omit<PaymentChecks, "revalidate" | "assertions"> | undefined {
  if (input.decryptionService === undefined) {
    if (input.persistence !== undefined) throw new WalletError("WALLET_INVALID_PAYMENT");
    return undefined;
  }
  const persistence = input.persistence;
  return {
    client: input.client,
    genesisHash: input.decryptionService.genesisHash,
    persistence: persistence && {
      wallet: input.wallet,
      store: persistence.store,
      cipher: persistence.cipher,
    },
  };
}

function buildAuthorizedTransaction(
  input: PrivateTransactionParams,
  transaction: Parameters<typeof authorizePrivateTransaction>[0],
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
): Promise<Transaction>;
function buildAuthorizedTransaction(
  input: PrivateTransactionParams,
  transaction: Parameters<typeof authorizePrivateTransaction>[0],
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
  payment: PaymentChecks | undefined,
): Promise<Transaction | PreparedPayment>;
async function buildAuthorizedTransaction(
  input: PrivateTransactionParams,
  transaction: Parameters<typeof authorizePrivateTransaction>[0],
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
  payment?: PaymentChecks,
): Promise<Transaction | PreparedPayment> {
  const reservationId = transaction._reservationId();
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
    const assembled = await withProofDataRetry(
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
    if (payment === undefined) return assembled;
    await payment.revalidate();
    const authorizedMaterial = authorizedPrivateTransactionMaterial(authorized);
    if (authorizedMaterial === undefined) throw new WalletError("WALLET_INTENT_MISMATCH");
    const approvedIntent = intentHash(authorizedMaterial.intent);
    const genesisHash = address(payment.genesisHash);
    const persistence = payment.persistence;
    const wallet = input.wallet;
    return prepareServicePayment(
      assembled,
      payment.client,
      payment.revalidate,
      payment.assertions,
      reservationId === undefined
        ? undefined
        : {
            assertActive() {
              if (
                !wallet
                  ._activeReservations(BigInt(Date.now()))
                  .some(({ id }) => id === reservationId)
              ) {
                throw new WalletError("WALLET_UNSIGNED_INPUT_UNAVAILABLE");
              }
            },
            release() {
              wallet._settleSubmission(reservationId);
            },
            assertPending(signature) {
              if (!wallet._canBroadcastSubmission(reservationId, signature))
                throw new WalletError("WALLET_UNSIGNED_INPUT_UNAVAILABLE");
            },
            async stage(signature, lifetime, signal) {
              const begin = () => {
                signal.throwIfAborted();
                if (
                  !wallet._beginSubmission(
                    {
                      id: reservationId,
                      signature,
                      ...lifetime,
                      genesisHash,
                      intentHash: approvedIntent,
                    },
                    BigInt(Date.now()),
                  )
                ) {
                  throw new WalletError("WALLET_UNSIGNED_INPUT_UNAVAILABLE");
                }
              };
              if (persistence === undefined) {
                begin();
                return;
              }
              await wallet._withSyncLock(async () => {
                begin();
                await saveWalletSnapshot(persistence, { signal });
              });
            },
          },
    );
  } catch (cause) {
    if (reservationId !== undefined) input.wallet._releaseReservation(reservationId);
    throw cause;
  }
}

export type { TransferDestination } from "./actions.js";
