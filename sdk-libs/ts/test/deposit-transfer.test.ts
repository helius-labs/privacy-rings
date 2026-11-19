import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { prepareTransfer } from "../src/client/prover/assembly.js";
import { decodeIndexedInputs } from "../src/client/prover/indexed.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
} from "../src/transaction/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

describe("ConfidentialTransfer.newDeposit", () => {
  it("opens its tree from a random slot 0 and refuses compact padding there", async () => {
    await initializePoseidon();
    const funder = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const transfer = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 7, PAYER);
    transfer.deposit(SOL_MINT, 5n, { kind: "sol", funder: PAYER });
    transfer.send(recipient, SOL_MINT, 5n);

    const proof = transfer.sign(funder, new AssetRegistry());
    expect(proof.inputUtxos.every((input) => input.isDummy() && input.treeId === 7)).toBe(true);
    expect(proof.outputTreeId).toBe(7);
    expect(proof.firstNullifier()).toEqual(proof.inputUtxos[0]?.nullifier());
    expect(proof.outputs[0]?.amount).toBe(5n);
    expect(proof.externalData.interfaceTransfers).toEqual([
      { kind: "sol", isDeposit: true, amount: 5n, userSolAccount: PAYER },
    ]);
    const prepared = prepareTransfer(proof).inputs;
    expect(decodeIndexedInputs(prepared).trees.map((tree) => tree.id)).toEqual([7]);
    const [input, ...inputs] = prepared.payload.inputs;
    const [lookup, ...lookups] = prepared.lookups;
    const compactFirst = {
      ...prepared,
      payload: { ...prepared.payload, inputs: [{ ...input, nullifier: 0n }, ...inputs] },
      lookups: [{ ...lookup, nullifier: proof.firstNullifier() }, ...lookups],
    };
    expect(() => decodeIndexedInputs(compactFirst)).toThrow();
  });

  it("refuses a dummy outside newDeposit, a recipient past the deposit, a source of another asset and a 33rd leg", async () => {
    await initializePoseidon();
    const funder = ShieldedKeypair.generate();
    expect(
      () =>
        new ConfidentialTransfer(
          funder.shieldedAddress(),
          [ProofInputUtxo.dummy(undefined, 0)],
          PAYER,
        ),
    ).toThrow("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED");
    const transfer = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 0, PAYER);
    expect(() => transfer.deposit(PAYER, 1n, { kind: "sol", funder: PAYER })).toThrow(
      "TRANSACTION_DEPOSIT_ASSET_MISMATCH",
    );
    transfer.deposit(SOL_MINT, 5n, { kind: "sol", funder: PAYER });
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 6n);
    expect(() => transfer.prepare()).toThrow("TRANSACTION_INSUFFICIENT_BALANCE");

    const hashLegs = (count: number) => () => {
      const wide = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 0, PAYER);
      for (let leg = 0; leg < count; leg += 1) {
        wide.deposit(SOL_MINT, 1n, { kind: "sol", funder: PAYER });
      }
      return wide.sign(funder, new AssetRegistry()).externalData.hash();
    };
    expect(hashLegs(32)).not.toThrow();
    expect(hashLegs(33)).toThrow("TRANSACTION_TOO_MANY_INTERFACE_TRANSFERS");
  });
});
