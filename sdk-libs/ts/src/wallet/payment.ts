import { ed25519 } from "@noble/curves/ed25519.js";
import {
  assertIsSendableTransaction,
  address,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  getSignatureFromTransaction,
  getTransactionDecoder,
  getTransactionEncoder,
  isTransactionWithBlockhashLifetime,
  signatureBytes,
  type SendableTransaction,
} from "@solana/kit";

import { withRequestSignal, type LatestBlockhash } from "../client/kit.js";
import type { PreparedPayment, TransactionBroadcaster } from "../client/ports.js";
import { equalBytes } from "../interface/bytes.js";
import type { RequestContext, Signature, Transaction } from "../interface/types.js";
import { WalletError, wrapWalletError } from "./error.js";

const addressEncoder = getAddressEncoder();
const encoder = getTransactionEncoder();
const decoder = getTransactionDecoder();

function checkedSignatureTransaction(
  prepared: Transaction,
  signed: Transaction,
): Transaction & SendableTransaction {
  if (
    !(signed?.messageBytes instanceof Uint8Array) ||
    !equalBytes(signed.messageBytes, Uint8Array.from(prepared.messageBytes))
  ) {
    throw new WalletError("WALLET_INTENT_MISMATCH", { details: { field: "signedMessage" } });
  }
  const required = Object.keys(prepared.signatures).map(address);
  if (
    required.length === 0 ||
    signed.signatures === null ||
    typeof signed.signatures !== "object" ||
    Object.keys(signed.signatures).length !== required.length
  ) {
    throw new WalletError("WALLET_PAYMENT_SIGNATURES");
  }
  const message = Uint8Array.from(prepared.messageBytes);
  const signatures = Object.fromEntries(
    required.map((address) => {
      const provided = signed.signatures[address];
      if (!(provided instanceof Uint8Array) || provided.length !== 64) {
        throw new WalletError("WALLET_PAYMENT_SIGNATURES");
      }
      const signature = signatureBytes(Uint8Array.from(provided));
      if (
        !ed25519.verify(signature, message, Uint8Array.from(addressEncoder.encode(address)), {
          zip215: false,
        })
      ) {
        throw new WalletError("WALLET_PAYMENT_SIGNATURES");
      }
      return [address, signature];
    }),
  );
  const checked = Object.freeze({ ...prepared, signatures: Object.freeze(signatures) });
  assertIsSendableTransaction(checked);
  return checked;
}

/** Give the signer a copy, then revalidate and submit the verified message. */
export function prepareServicePayment(
  transaction: Transaction,
  client: TransactionBroadcaster,
  revalidate: (context?: RequestContext) => Promise<void>,
  reservation?: Readonly<{
    assertActive(): void;
    stage(
      signature: Signature,
      lifetime: LatestBlockhash & { blockhashValidAtSlot: bigint },
      signal: AbortSignal,
    ): Promise<void>;
    assertPending(signature: Signature): void;
    release(): void;
  }>,
): PreparedPayment {
  if (!isTransactionWithBlockhashLifetime(transaction))
    throw new WalletError("WALLET_PAYMENT_BLOCKHASH");
  const { blockhash, lastValidBlockHeight } = transaction.lifetimeConstraint;
  if (
    lastValidBlockHeight < 0n ||
    lastValidBlockHeight > 0xffff_ffff_ffff_ffffn ||
    getCompiledTransactionMessageDecoder().decode(transaction.messageBytes).lifetimeToken !==
      blockhash
  )
    throw new WalletError("WALLET_PAYMENT_BLOCKHASH");
  const unsigned = Uint8Array.from(encoder.encode(transaction));
  const getBlockhashValidity = client.getBlockhashValidity.bind(client);
  async function validAtSlot(signal: AbortSignal): Promise<bigint> {
    const { slot, valid } = await getBlockhashValidity(blockhash, { signal });
    if (valid !== true || typeof slot !== "bigint" || slot < 0n || slot > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_PAYMENT_BLOCKHASH");
    }
    return slot;
  }
  const broadcast = client.broadcastTransaction.bind(client);
  let used = false;
  return Object.freeze<PreparedPayment>({
    async send(sign, context) {
      if (used)
        throw new WalletError("WALLET_SUBMIT_PAYMENT", {
          causeCode: "WALLET_PAYMENT_ALREADY_USED",
        });
      used = true;
      let attempted: Signature | undefined;
      try {
        return await withRequestSignal(
          "sendPayment",
          { ...context, timeoutMs: context?.timeoutMs ?? 60_000 },
          async (signal) => {
            reservation?.assertActive();
            const signed = await sign(decoder.decode(unsigned.slice()), signal);
            signal.throwIfAborted();
            const checked = checkedSignatureTransaction(decoder.decode(unsigned), signed);
            const expected = getSignatureFromTransaction(checked);
            let blockhashValidAtSlot = 0n;
            if (reservation) {
              blockhashValidAtSlot = await validAtSlot(signal);
              signal.throwIfAborted();
              await reservation.stage(
                expected,
                { blockhash, lastValidBlockHeight, blockhashValidAtSlot },
                signal,
              );
            }
            signal.throwIfAborted();
            await revalidate({ signal });
            signal.throwIfAborted();
            if ((await validAtSlot(signal)) < blockhashValidAtSlot) {
              throw new WalletError("WALLET_PAYMENT_BLOCKHASH");
            }
            signal.throwIfAborted();
            reservation?.assertPending(expected);
            attempted = expected;
            if ((await broadcast(checked, { signal })) !== expected) {
              throw new WalletError("WALLET_INTENT_MISMATCH", {
                details: { field: "rpcSignature" },
              });
            }
            return expected;
          },
        );
      } catch (cause) {
        if (attempted === undefined) reservation?.release();
        throw wrapWalletError(
          "WALLET_SUBMIT_PAYMENT",
          cause,
          attempted === undefined ? undefined : { transactionId: attempted },
        );
      }
    },
    cancel() {
      if (used) return;
      used = true;
      reservation?.release();
    },
  });
}
