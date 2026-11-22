import {
  generateKeyPairSigner,
  getSignatureFromTransaction,
  signTransactionWithSigners,
  signatureBytes,
  type Transaction,
} from "@solana/kit";
import { expect, it, vi } from "vitest";

import { buildDepositTransaction, ShieldedKeypair } from "../src/index.js";
import { depositClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";

const GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

async function payment() {
  const payer = await generateKeyPairSigner();
  const recipient = ShieldedKeypair.generate().shieldedAddress();
  const address = vi.fn(async () => recipient);
  const broadcastTransaction = vi.fn(async (transaction: Transaction) =>
    getSignatureFromTransaction(transaction),
  );
  const prepared = await buildDepositTransaction({
    client: { ...depositClient({ broadcastTransaction }), getGenesisHash: async () => GENESIS },
    decryptionService: { address, genesisHash: GENESIS },
    feePayer: payer.address,
    recipient: recipient.solanaAddress(),
    amount: 5n,
  });
  const sign = (transaction: Transaction) => signTransactionWithSigners([payer], transaction);
  return { prepared, payer, recipient, sign, address, broadcastTransaction };
}

it("refuses a different Solana message from the signing callback", async () => {
  const { prepared, payer, sign, address, broadcastTransaction } = await payment();
  await expect(prepared.send(() => sign(emptyTransaction(payer.address)))).rejects.toMatchObject({
    code: "WALLET_SUBMIT_PAYMENT",
    causeCode: "WALLET_INTENT_MISMATCH",
  });
  expect(address).toHaveBeenCalledTimes(2);
  expect(broadcastTransaction).not.toHaveBeenCalled();
});

it.each(["missing", "forged", "extra"] as const)(
  "refuses %s transaction signatures",
  async (fault) => {
    const { prepared, payer, sign, broadcastTransaction } = await payment();
    const other = await generateKeyPairSigner();
    const fake = signatureBytes(new Uint8Array(64));
    await expect(
      prepared.send(async (transaction) => {
        if (fault === "missing") return transaction;
        const signed = await sign(transaction);
        return {
          ...signed,
          signatures: {
            ...signed.signatures,
            [fault === "forged" ? payer.address : other.address]: fake,
          },
        };
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SUBMIT_PAYMENT",
      causeCode: "WALLET_PAYMENT_SIGNATURES",
    });
    expect(broadcastTransaction).not.toHaveBeenCalled();
  },
);

it("aborts a signer that ignores cancellation and never broadcasts", async () => {
  const { prepared, broadcastTransaction } = await payment();
  const controller = new AbortController();
  await expect(
    prepared.send(
      async (_transaction, signal) => {
        controller.abort();
        expect(signal.aborted).toBe(true);
        return new Promise<Transaction>(() => {});
      },
      { signal: controller.signal },
    ),
  ).rejects.toMatchObject({
    code: "WALLET_SUBMIT_PAYMENT",
    causeCode: "CLIENT_ABORTED",
  });
  expect(broadcastTransaction).not.toHaveBeenCalled();
});

it("submits a prepared payment once, even when a second caller enters during signing", async () => {
  const { prepared, address, sign, broadcastTransaction } = await payment();
  const first = prepared.send(sign);
  await expect(prepared.send(sign)).rejects.toMatchObject({
    causeCode: "WALLET_PAYMENT_ALREADY_USED",
  });
  expect(await first).toBe(getSignatureFromTransaction(broadcastTransaction.mock.calls[0]![0]));
  expect(address).toHaveBeenCalledTimes(3);
  expect(broadcastTransaction).toHaveBeenCalledOnce();
});

it("submits a private copy of the signatures after an asynchronous recipient refresh", async () => {
  const { prepared, payer, recipient, sign, address, broadcastTransaction } = await payment();
  let signerBytes = new Uint8Array();
  address.mockImplementationOnce(async () => {
    signerBytes.fill(0);
    return recipient;
  });
  const signature = await prepared.send(async (transaction) => {
    const signed = await sign(transaction);
    signerBytes = new Uint8Array(signed.signatures[payer.address]!);
    return { ...signed, signatures: { [payer.address]: signatureBytes(signerBytes) } };
  });
  expect(signerBytes).toEqual(new Uint8Array(64));
  expect(signature).toBe(getSignatureFromTransaction(broadcastTransaction.mock.calls[0]![0]));
});

it("refuses an RPC acknowledgement for a different signature", async () => {
  const { prepared, payer, sign, broadcastTransaction } = await payment();
  broadcastTransaction.mockResolvedValueOnce(
    getSignatureFromTransaction(await sign(emptyTransaction(payer.address))),
  );
  await expect(prepared.send(sign)).rejects.toMatchObject({
    code: "WALLET_SUBMIT_PAYMENT",
    causeCode: "WALLET_INTENT_MISMATCH",
  });
  expect(broadcastTransaction).toHaveBeenCalledOnce();
});
