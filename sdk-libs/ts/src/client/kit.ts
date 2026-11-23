import {
  createSolanaRpc,
  createSolanaRpcFromTransport,
  createSolanaRpcSubscriptions,
  getSolanaErrorFromTransactionError,
  isSolanaError,
  setTransactionMessageLifetimeUsingBlockhash,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN,
  SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,
  SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN,
  SolanaError,
  type Blockhash,
  type Commitment,
  type Rpc,
  type RpcResponse,
  type RpcSubscriptions,
  type RpcTransport,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
} from "@solana/kit";
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from "@solana/rpc-spec-types";

import type { RequestContext } from "../interface/types.js";
import { decodeBatch, wireDecoder } from "../interface/decode.js";

import { ClientError, isClientError } from "./error.js";
import { composeSignal, requestError, untilAborted, type ComposedSignal } from "./internal.js";

export type SolanaRpc = Rpc<SolanaRpcApi>;
export type SolanaRpcSubscriptions = RpcSubscriptions<SolanaRpcSubscriptionsApi>;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const isU64 = (value: unknown): value is bigint =>
  typeof value === "bigint" && value >= 0n && value <= MAX_U64;

export interface LatestBlockhash {
  readonly blockhash: Parameters<
    typeof setTransactionMessageLifetimeUsingBlockhash
  >[0]["blockhash"];
  readonly lastValidBlockHeight: bigint;
}

/**
 * Without `fetch`, Solana RPC uses Kit's default transport and the global
 * `fetch`. Subscriptions use a WebSocket either way.
 */
export function createKitClients(
  input: Readonly<{
    solanaRpcUrl: string | URL;
    solanaRpcSubscriptionsUrl?: string | URL;
    fetch?: typeof globalThis.fetch;
  }>,
): Readonly<{ solanaRpc: SolanaRpc; solanaRpcSubscriptions: SolanaRpcSubscriptions }> {
  const rpcUrl = urlString(input.solanaRpcUrl, "solanaRpcUrl", ["http:", "https:"]);
  const subscriptionsUrl =
    input.solanaRpcSubscriptionsUrl === undefined
      ? defaultSolanaRpcSubscriptionsUrl(rpcUrl)
      : urlString(input.solanaRpcSubscriptionsUrl, "solanaRpcSubscriptionsUrl", ["ws:", "wss:"]);
  return Object.freeze({
    solanaRpc:
      input.fetch === undefined
        ? createSolanaRpc(rpcUrl)
        : createSolanaRpcFromTransport(fetchRpcTransport(rpcUrl, input.fetch)),
    solanaRpcSubscriptions: createSolanaRpcSubscriptions(subscriptionsUrl),
  });
}

/**
 * Kit's Solana RPC HTTP transport over a caller's `fetch`: integers cross the
 * wire as bigints and a non-2xx status throws Kit's
 * `SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR`. Identical concurrent requests are
 * not coalesced.
 */
function fetchRpcTransport(url: string, fetch: typeof globalThis.fetch): RpcTransport {
  return async <TResponse>({
    payload,
    signal,
  }: Parameters<RpcTransport>[0]): Promise<RpcResponse<TResponse>> => {
    const response = await fetch(url, {
      body: stringifyJsonWithBigInts(payload),
      headers: { accept: "application/json", "content-type": "application/json; charset=utf-8" },
      method: "POST",
      ...(signal === undefined ? {} : { signal }),
    });
    if (!response.ok) {
      throw new SolanaError(SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR, {
        headers: response.headers,
        message: response.statusText,
        statusCode: response.status,
      });
    }
    // Kit's RPC layer applies the method's response transformers to this value.
    return parseJsonWithBigInts(await response.text()) as RpcResponse<TResponse>;
  };
}

export async function runKitRpc<T>(
  method: string,
  context: RequestContext | undefined,
  operation: (abortSignal: AbortSignal) => Promise<T>,
): Promise<T> {
  const signal = composeSignal(context, method);
  try {
    return await untilAborted(operation(signal.signal), signal, () => requestError(method, signal));
  } catch (cause) {
    throw operationError(method, signal, cause);
  } finally {
    signal.cleanup();
  }
}

export async function readFinalizedEpochInfo(rpc: SolanaRpc, context?: RequestContext) {
  const method = "getEpochInfo";
  const response: unknown = await runKitRpc(method, context, (abortSignal) =>
    rpc.getEpochInfo({ commitment: "finalized" }).send({ abortSignal }),
  );
  const invalid = (reason: string) =>
    new ClientError("CLIENT_RPC", { details: { method, reason } });
  const { absoluteSlot, blockHeight } = wireDecoder(invalid).record(response, "result");
  if (!isU64(absoluteSlot)) throw invalid("absoluteSlot");
  if (!isU64(blockHeight)) throw invalid("blockHeight");
  return { absoluteSlot, blockHeight };
}

export async function readBlockhashValidity(
  rpc: SolanaRpc,
  blockhash: Blockhash,
  config: Readonly<{ commitment: Commitment; minContextSlot?: bigint }>,
  context?: RequestContext,
) {
  const method = "isBlockhashValid";
  const response: unknown = await runKitRpc(method, context, (abortSignal) =>
    rpc.isBlockhashValid(blockhash, config).send({ abortSignal }),
  );
  const invalid = (reason: string) =>
    new ClientError("CLIENT_RPC", { details: { method, reason } });
  const decode = wireDecoder(invalid);
  const result = decode.record(response, "result");
  const slot = decode.record(result["context"], "context")["slot"];
  if (!isU64(slot) || slot < (config.minContextSlot ?? 0n)) {
    throw invalid("context.slot");
  }
  return { slot, valid: decode.boolean(result["value"], "value") };
}

/** True for each signature that might have executed successfully. */
export async function readSignatureHistory(
  rpc: SolanaRpc,
  signatures: readonly Signature[],
  minContextSlot: bigint,
  context?: RequestContext,
): Promise<readonly boolean[]> {
  const method = "getSignatureStatuses";
  const response: unknown = await runKitRpc(method, context, (abortSignal) =>
    rpc.getSignatureStatuses(signatures, { searchTransactionHistory: true }).send({ abortSignal }),
  );
  const invalid = (reason: string) =>
    new ClientError("CLIENT_RPC", { details: { method, reason } });
  const decode = wireDecoder(invalid);
  const result = decode.record(response, "result");
  const slot = decode.record(result["context"], "context")["slot"];
  if (!isU64(slot) || slot < minContextSlot) throw invalid("context.slot");
  return decodeBatch(
    result["value"],
    signatures.length,
    (entry) => {
      if (entry === null) return false;
      const status = decode.record(entry, "value");
      const landed = status["slot"];
      if (!isU64(landed) || landed > slot) throw invalid("value.slot");
      const finality = status["confirmationStatus"];
      if (
        finality !== null &&
        finality !== "processed" &&
        finality !== "confirmed" &&
        finality !== "finalized"
      )
        throw invalid("value.confirmationStatus");
      const confirmations = status["confirmations"];
      if (
        (confirmations !== null && !isU64(confirmations)) ||
        (finality !== null && (finality === "finalized") !== (confirmations === null))
      )
        throw invalid("value.confirmations");
      const error = status["err"];
      if (error === null) return true;
      requireTransactionFailure(error, () => invalid("value.err"));
      return finality !== "finalized";
    },
    () => invalid("value"),
  );
}

function requireTransactionFailure(value: unknown, invalid: () => ClientError): void {
  const decode = wireDecoder(invalid);
  const single = (object: Record<string, unknown>): string => {
    const [key, ...extra] = Reflect.ownKeys(object);
    if (typeof key !== "string" || extra.length !== 0) throw invalid();
    return key;
  };
  const unsigned = (item: unknown, max: number): boolean =>
    ((typeof item === "number" && Number.isInteger(item)) || typeof item === "bigint") &&
    item >= 0 &&
    item <= max;
  const error = typeof value === "string" ? value : decode.record(value, "err");
  const variant = typeof error === "string" ? error : single(error);
  const payload = typeof error === "string" ? undefined : error[variant];
  switch (variant) {
    case "InstructionError": {
      const [index, instruction, ...extra] = decode.list(payload, "InstructionError");
      if (extra.length !== 0 || !unsigned(index, 0xff)) throw invalid();
      if (typeof instruction !== "string") {
        const fields = decode.record(instruction, "InstructionError");
        if (single(fields) !== "Custom" || !unsigned(fields["Custom"], 0xffff_ffff))
          throw invalid();
      } else if (instruction === "Custom") throw invalid();
      break;
    }
    case "DuplicateInstruction":
      if (!unsigned(payload, 0xff)) throw invalid();
      break;
    case "InsufficientFundsForRent":
    case "ProgramExecutionTemporarilyRestricted": {
      const fields = decode.record(payload, variant);
      if (single(fields) !== "account_index" || !unsigned(fields["account_index"], 0xff))
        throw invalid();
      break;
    }
    default:
      if (typeof error !== "string") throw invalid();
  }
  const mapped = getSolanaErrorFromTransactionError(error);
  if (
    isSolanaError(mapped, SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN) ||
    isSolanaError(mapped, SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN)
  )
    throw invalid();
}

/** Bound a flow that includes callbacks outside the SDK's RPC transport. */
export async function withRequestSignal<T>(
  method: string,
  context: RequestContext | undefined,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const scope = composeSignal(context, method);
  try {
    return await untilAborted(operation(scope.signal), scope, () => requestError(method, scope));
  } finally {
    scope.cleanup();
  }
}

function operationError(method: string, signal: ComposedSignal, cause: unknown): ClientError {
  if (isClientError(cause)) return cause;
  if (isSolanaError(cause, SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND)) {
    return new ClientError("CLIENT_UNSUPPORTED_RPC_METHOD", {
      details: { method },
      cause,
    });
  }
  if (signal.timedOut()) {
    return new ClientError("CLIENT_TIMEOUT", {
      details: { method, retryable: true },
      cause,
    });
  }
  if (signal.signal.aborted) {
    return new ClientError("CLIENT_ABORTED", {
      details: { method, retryable: false },
      cause,
    });
  }
  return new ClientError("CLIENT_RPC", {
    details: { method },
    cause,
  });
}

function urlString(value: string | URL, field: string, protocols: readonly string[]): string {
  let url: URL;
  try {
    url = new URL(value instanceof URL ? value.href : value);
  } catch {
    throw invalidUrl(field);
  }
  if (
    !protocols.includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  ) {
    throw invalidUrl(field);
  }
  return url.href;
}

export function defaultSolanaRpcSubscriptionsUrl(value: string): string {
  const url = new URL(value);
  if (url.port !== "") {
    const port = Number(url.port);
    if (!Number.isSafeInteger(port) || port >= 65_535) {
      throw invalidUrl("solanaRpcUrl");
    }
    url.port = String(port + 1);
  }
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  return url.href;
}

function invalidUrl(field: string): ClientError {
  return new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
}
