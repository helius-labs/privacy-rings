import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "../src/interface/index.js";
import type { RpcAccount } from "../src/client/rpc.js";
import {
  decodeTransferFeeConfig,
  quoteSplDeposit,
  splDepositAmounts,
} from "../src/wallet/transfer-fee.js";

const MINT = address("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
const CLOCK = address("SysvarC1ock11111111111111111111111111111111");
const U64_MAX = 0xffff_ffff_ffff_ffffn;

interface Fee {
  epoch?: bigint;
  maximumFee: bigint;
  basisPoints: number;
}

/** Token-2022 mint bytes: base, padding, account type, one TransferFeeConfig TLV. */
function feeMint(older: Fee, newer: Fee = older): Uint8Array {
  const data = new Uint8Array(166 + 4 + 108);
  const view = new DataView(data.buffer);
  data[45] = 9; // decimals
  data[46] = 1; // initialized
  data[165] = 1; // AccountType::Mint
  view.setUint16(166, 1, true); // ExtensionType::TransferFeeConfig
  view.setUint16(168, 108, true);
  const writeFee = (offset: number, fee: Fee) => {
    view.setBigUint64(offset, fee.epoch ?? 0n, true);
    view.setBigUint64(offset + 8, fee.maximumFee, true);
    view.setUint16(offset + 16, fee.basisPoints, true);
  };
  writeFee(170 + 72, older);
  writeFee(170 + 90, newer);
  return data;
}

function account(data: Uint8Array, owner = SPL_TOKEN_2022_PROGRAM_ID): RpcAccount {
  return { owner, data, lamports: 1n };
}

describe("transfer-fee deposit sizing", () => {
  it.each([
    // [bps, max fee, amount, gross], matching the program tests
    [100, U64_MAX, 400n, 405n],
    [500, U64_MAX, 1_000_000n, 1_052_632n],
    [500, 10n, 1_000_000n, 1_000_010n],
    [10_000, 25n, 400n, 425n],
    [0, U64_MAX, 400n, 400n],
  ] as const)("bps %i cap %s: %s nominal debits %s", (bps, max, amount, gross) => {
    const mint = account(feeMint({ basisPoints: bps, maximumFee: max }));
    expect(splDepositAmounts(mint, amount, 0n)).toEqual({
      amount,
      gross,
      fee: gross - amount,
    });
  });

  it("debits the nominal amount for mints without a transfer fee", () => {
    const legacy: RpcAccount = {
      owner: SPL_TOKEN_PROGRAM_ID,
      data: new Uint8Array(82),
      lamports: 1n,
    };
    expect(splDepositAmounts(legacy, 400n, 0n)).toEqual({
      amount: 400n,
      gross: 400n,
      fee: 0n,
    });
    expect(decodeTransferFeeConfig(new Uint8Array(82))).toBeUndefined();
  });

  it("uses the newer fee from its epoch on", () => {
    const mint = account(
      feeMint(
        { basisPoints: 100, maximumFee: U64_MAX },
        { epoch: 7n, basisPoints: 500, maximumFee: U64_MAX },
      ),
    );
    expect(splDepositAmounts(mint, 1_000_000n, 6n).gross).toBe(1_010_102n);
    expect(splDepositAmounts(mint, 1_000_000n, 7n).gross).toBe(1_052_632n);
  });

  it("refuses an amount no gross can credit exactly", () => {
    const mint = account(feeMint({ basisPoints: 10_000, maximumFee: U64_MAX }));
    expect(() => splDepositAmounts(mint, 400n, 0n)).toThrow();
  });

  it("quotes from the mint and the clock sysvar", async () => {
    const clock = new Uint8Array(40);
    new DataView(clock.buffer).setBigUint64(16, 3n, true);
    const accounts = new Map<string, RpcAccount>([
      [MINT, account(feeMint({ basisPoints: 100, maximumFee: U64_MAX }))],
      [CLOCK, { owner: CLOCK, data: clock, lamports: 1n }],
    ]);
    const quote = await quoteSplDeposit({
      client: { getAccount: async (key) => accounts.get(key) },
      asset: MINT,
      amount: 400n,
    });
    expect(quote).toEqual({ amount: 400n, gross: 405n, fee: 5n });
  });
});
