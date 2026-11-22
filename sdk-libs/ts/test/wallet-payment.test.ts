import {
  generateKeyPairSigner,
  getSignatureFromTransaction,
  signTransactionWithSigners,
  signatureBytes,
  type Transaction,
} from "@solana/kit";
import { expect, it, vi } from "vitest";

import { buildDepositTransaction, ShieldedAddress, ShieldedKeypair } from "../src/index.js";
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
  const getBlockhashValidity = vi.fn(async () => ({ slot: 1n, valid: true }));
  const prepared = await buildDepositTransaction({
    client: {
      ...depositClient({ broadcastTransaction, getBlockhashValidity }),
      getGenesisHash: async () => GENESIS,
    },
    decryptionService: { address, genesisHash: GENESIS },
    feePayer: payer.address,
    recipient: recipient.solanaAddress(),
    amount: 5n,
  });
  const sign = (transaction: Transaction) => signTransactionWithSigners([payer], transaction);
  return { prepared, payer, recipient, sign, address, broadcastTransaction, getBlockhashValidity };
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
  expect(address).toHaveBeenCalledTimes(4);
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
    details: { transactionId: expect.any(String) },
  });
  expect(broadcastTransaction).toHaveBeenCalledOnce();
});

it.each(["signing", "recipient lookup"] as const)(
  "refuses a blockhash that expires during %s",
  async (phase) => {
    const { prepared, sign, address, recipient, getBlockhashValidity, broadcastTransaction } =
      await payment();
    const expires = () => getBlockhashValidity.mockResolvedValueOnce({ slot: 2n, valid: false });
    if (phase === "recipient lookup")
      address.mockImplementationOnce(async () => {
        expires();
        return recipient;
      });
    await expect(
      prepared.send(async (transaction) => {
        if (phase === "signing") expires();
        return sign(transaction);
      }),
    ).rejects.toMatchObject({ causeCode: "WALLET_PAYMENT_BLOCKHASH" });
    expect(getBlockhashValidity).toHaveBeenCalledOnce();
    expect(address).toHaveBeenCalledTimes(3);
    expect(broadcastTransaction).not.toHaveBeenCalled();
  },
);

it("refuses a recipient change during the blockhash check", async () => {
  const { prepared, sign, recipient, address, broadcastTransaction, getBlockhashValidity } =
    await payment();
  const changed = ShieldedKeypair.generate().shieldedAddress();
  getBlockhashValidity.mockImplementationOnce(async () => {
    address.mockResolvedValueOnce(
      ShieldedAddress.fromPublicKeys(
        recipient.signingPublicKey,
        recipient.nullifierPublicKey,
        changed.viewingPublicKey,
      ),
    );
    return { slot: 2n, valid: true };
  });
  await expect(prepared.send(sign)).rejects.toMatchObject({
    code: "WALLET_SUBMIT_PAYMENT",
    causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH",
  });
  expect(getBlockhashValidity).toHaveBeenCalledOnce();
  expect(broadcastTransaction).not.toHaveBeenCalled();
});

it("keeps the managed submission path when the caller edits its builder arguments", async () => {
  const payer = await generateKeyPairSigner();
  const recipient = ShieldedKeypair.generate().shieldedAddress();
  const broadcastTransaction = vi.fn(async (transaction: Transaction) =>
    getSignatureFromTransaction(transaction),
  );
  const client = depositClient({ broadcastTransaction });
  const parameters = {
    client: {
      ...client,
      getGenesisHash: async () => GENESIS,
      async getLatestBlockhash() {
        Object.defineProperty(parameters, "decryptionService", { value: undefined });
        return client.getLatestBlockhash();
      },
    },
    decryptionService: { address: async () => recipient, genesisHash: GENESIS },
    feePayer: payer.address,
    recipient: recipient.solanaAddress(),
    amount: 5n,
  };
  const prepared = await buildDepositTransaction(parameters);
  await prepared.send((transaction) => signTransactionWithSigners([payer], transaction));
  expect(broadcastTransaction).toHaveBeenCalledOnce();
});
