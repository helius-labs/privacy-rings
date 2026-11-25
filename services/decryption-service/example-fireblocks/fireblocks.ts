import { setTimeout } from "node:timers/promises";
import {
  TransactionOperation,
  TransferPeerPathType,
  type Fireblocks,
  type TransactionResponse,
} from "@fireblocks/ts-sdk";
import {
  address,
  getPublicKeyFromAddress,
  signatureBytes,
  verifySignature,
  type MessagePartialSigner,
  type TransactionPartialSigner,
} from "@solana/kit";

type FireblocksApi = {
  createTransaction(input: NonNullable<Parameters<Fireblocks["transactions"]["createTransaction"]>[0]>):
    Promise<{ data: { id?: string } }>;
  getTransaction(input: Parameters<Fireblocks["transactions"]["getTransaction"]>[0]):
    Promise<{ data: Pick<TransactionResponse, "status" | "subStatus" | "signedMessages"> }>;
};

/** Raw signing preserves the SDK's exact approval and v1 transaction message bytes. */
export function fireblocksSigner(
  client: FireblocksApi,
  vaultAccountId: string,
  walletAddress: string,
): MessagePartialSigner & TransactionPartialSigner {
  const signer = address(walletAddress);
  const publicKey = getPublicKeyFromAddress(signer);

  async function sign(content: Parameters<typeof verifySignature>[2]) {
    const { data: created } = await client.createTransaction({
      transactionRequest: {
        operation: TransactionOperation.Raw,
        assetId: "SOL_TEST",
        source: { type: TransferPeerPathType.VaultAccount, id: vaultAccountId },
        extraParameters: {
          rawMessageData: {
            messages: [{ content: Buffer.from(content).toString("hex") }],
          },
        },
      },
    });
    if (!created.id) throw new Error("Fireblocks returned no transaction ID");

    for (let attempt = 0; attempt < 60; attempt++) {
      const { data: result } = await client.getTransaction({ txId: created.id });
      if (result.status === "COMPLETED") {
        const hex = result.signedMessages?.[0]?.signature?.fullSig;
        if (!hex || !/^[0-9a-fA-F]{128}$/.test(hex)) {
          throw new Error("Fireblocks returned a malformed Ed25519 signature");
        }
        const signature = signatureBytes(new Uint8Array(Buffer.from(hex, "hex")));
        if (!(await verifySignature(await publicKey, signature, content))) {
          throw new Error("Fireblocks returned a signature for a different message or account");
        }
        return { [signer]: signature };
      }
      if (["FAILED", "REJECTED", "CANCELLED", "BLOCKED"].includes(result.status ?? "")) {
        throw new Error(`Fireblocks signing ${result.status}: ${result.subStatus ?? ""}`);
      }
      await setTimeout(1_000);
    }
    throw new Error(`Fireblocks signing timed out: ${created.id}`);
  }

  return {
    address: signer,
    async signMessages(messages) {
      const signatures = [];
      for (const { content } of messages) signatures.push(await sign(content));
      return signatures;
    },
    async signTransactions(transactions) {
      const signatures = [];
      for (const transaction of transactions) {
        if (!(signer in transaction.signatures)) throw new Error("Fireblocks account is not a transaction signer");
        signatures.push(await sign(transaction.messageBytes));
      }
      return signatures;
    },
  };
}
