import { address } from "@solana/kit";

import type { ChainReader } from "../client/ports.js";
import type { RpcAccount } from "../client/rpc.js";
import type { Address, RequestContext } from "../interface/types.js";
import { SPL_TOKEN_2022_PROGRAM_ID } from "../interface/program.js";
import { SOL_MINT } from "../transaction/asset.js";

import { WalletError, wrapWalletError } from "./error.js";

/** One epoch's Token-2022 transfer fee. */
export interface TransferFee {
  readonly epoch: bigint;
  readonly maximumFee: bigint;
  readonly basisPoints: number;
}

/** The two fees a Token-2022 `TransferFeeConfig` holds. */
export interface TransferFeeConfig {
  readonly olderTransferFee: TransferFee;
  readonly newerTransferFee: TransferFee;
}

/** What a deposit of `amount` debits: the vault is always credited `amount`. */
export interface SplDepositAmounts {
  /** The note amount and the vault credit. */
  readonly amount: bigint;
  /** What leaves the depositor's token account: `amount + fee`. */
  readonly gross: bigint;
  /** The mint's transfer fee, withheld in the vault and harvestable to the mint. */
  readonly fee: bigint;
}

const CLOCK_SYSVAR = address("SysvarC1ock11111111111111111111111111111111");
const CLOCK_EPOCH_OFFSET = 16;
// Token-2022 pads every extended account to the token-account length before
// the account-type byte, so the TLV area of a mint starts after it.
const ACCOUNT_TYPE_OFFSET = 165;
const ACCOUNT_TYPE_MINT = 1;
const EXTENSION_TRANSFER_FEE_CONFIG = 1;
const TRANSFER_FEE_CONFIG_LEN = 108;
const ONE_IN_BASIS_POINTS = 10_000n;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function readFee(view: DataView, offset: number): TransferFee {
  return {
    epoch: view.getBigUint64(offset, true),
    maximumFee: view.getBigUint64(offset + 8, true),
    basisPoints: view.getUint16(offset + 16, true),
  };
}

/**
 * The `TransferFeeConfig` of a Token-2022 mint's data, or undefined for a mint
 * without one (every SPL Token mint and Token-2022 mints without the extension).
 */
export function decodeTransferFeeConfig(data: Uint8Array): TransferFeeConfig | undefined {
  if (data.length <= ACCOUNT_TYPE_OFFSET) return undefined;
  if (data[ACCOUNT_TYPE_OFFSET] !== ACCOUNT_TYPE_MINT) return undefined;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = ACCOUNT_TYPE_OFFSET + 1;
  while (offset + 4 <= data.length) {
    const type = view.getUint16(offset, true);
    const length = view.getUint16(offset + 2, true);
    const value = offset + 4;
    if (type === 0) return undefined;
    if (value + length > data.length) return undefined;
    if (type === EXTENSION_TRANSFER_FEE_CONFIG) {
      if (length !== TRANSFER_FEE_CONFIG_LEN) return undefined;
      // Two authorities and the withheld amount precede the two fees.
      return {
        olderTransferFee: readFee(view, value + 72),
        newerTransferFee: readFee(view, value + 90),
      };
    }
    offset = value + length;
  }
  return undefined;
}

/** Token-2022 `TransferFeeConfig::get_epoch_fee`. */
export function epochTransferFee(config: TransferFeeConfig, epoch: bigint): TransferFee {
  return epoch >= config.newerTransferFee.epoch ? config.newerTransferFee : config.olderTransferFee;
}

/** Token-2022 `TransferFee::calculate_fee`: ceiling of `bps` of the amount, capped. */
export function calculateTransferFee(fee: TransferFee, preFeeAmount: bigint): bigint {
  const bps = BigInt(fee.basisPoints);
  if (bps === 0n || preFeeAmount === 0n) return 0n;
  const raw = (preFeeAmount * bps + ONE_IN_BASIS_POINTS - 1n) / ONE_IN_BASIS_POINTS;
  return raw < fee.maximumFee ? raw : fee.maximumFee;
}

/**
 * Token-2022 `TransferFee::calculate_pre_fee_amount`: the smallest gross whose
 * fee leaves `postFeeAmount`, or undefined when none fits in a u64.
 */
export function calculatePreFeeAmount(fee: TransferFee, postFeeAmount: bigint): bigint | undefined {
  const bps = BigInt(fee.basisPoints);
  let gross: bigint;
  if (bps === 0n) gross = postFeeAmount;
  else if (postFeeAmount === 0n) gross = 0n;
  else if (bps === ONE_IN_BASIS_POINTS) gross = fee.maximumFee + postFeeAmount;
  else {
    const denominator = ONE_IN_BASIS_POINTS - bps;
    const raw = (postFeeAmount * ONE_IN_BASIS_POINTS + denominator - 1n) / denominator;
    gross = raw - postFeeAmount >= fee.maximumFee ? postFeeAmount + fee.maximumFee : raw;
  }
  return gross > U64_MAX ? undefined : gross;
}

/**
 * The gross and fee of a deposit of `amount` of `mint`, as the shielded-pool
 * program computes them. A mint without a transfer fee debits `amount`.
 * Throws when no gross credits the vault exactly `amount`, which the program
 * rejects as well.
 */
export function splDepositAmounts(
  mint: RpcAccount | undefined,
  amount: bigint,
  epoch: bigint,
): SplDepositAmounts {
  const config =
    mint !== undefined && mint.owner === SPL_TOKEN_2022_PROGRAM_ID
      ? decodeTransferFeeConfig(mint.data)
      : undefined;
  if (config === undefined) return { amount, gross: amount, fee: 0n };
  const transferFee = epochTransferFee(config, epoch);
  const gross = calculatePreFeeAmount(transferFee, amount);
  const fee = gross === undefined ? undefined : calculateTransferFee(transferFee, gross);
  if (gross === undefined || fee === undefined || gross - fee !== amount) {
    throw new WalletError("WALLET_INVALID_AMOUNT", {
      details: {
        amount: amount.toString(),
        reason: "no transfer amount credits it exactly",
      },
    });
  }
  return { amount, gross, fee };
}

/**
 * What a deposit of `amount` of `asset` will debit from the depositor's token
 * account at the current epoch. Show `gross` to the user and make sure the
 * token account holds it; the note and the vault receive exactly `amount`.
 */
export async function quoteSplDeposit(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    asset: Address;
    amount: bigint;
  }>,
  context?: RequestContext,
): Promise<SplDepositAmounts> {
  try {
    if (input.asset === SOL_MINT) return { amount: input.amount, gross: input.amount, fee: 0n };
    const [mint, clock] = await Promise.all([
      input.client.getAccount(input.asset, context),
      input.client.getAccount(CLOCK_SYSVAR, context),
    ]);
    if (mint === undefined) {
      throw new WalletError("WALLET_ASSET_METADATA", {
        details: { mint: input.asset },
      });
    }
    if (clock === undefined || clock.data.length < CLOCK_EPOCH_OFFSET + 8) {
      throw new WalletError("WALLET_ASSET_METADATA", {
        details: { sysvar: CLOCK_SYSVAR },
      });
    }
    const epoch = new DataView(
      clock.data.buffer,
      clock.data.byteOffset,
      clock.data.byteLength,
    ).getBigUint64(CLOCK_EPOCH_OFFSET, true);
    return splDepositAmounts(mint, input.amount, epoch);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
  }
}
