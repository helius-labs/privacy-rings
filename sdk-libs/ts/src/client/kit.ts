import {
  createSolanaRpc,
  createSolanaRpcFromTransport,
  createSolanaRpcSubscriptions,
  isSolanaError,
  setTransactionMessageLifetimeUsingBlockhash,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,
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
  if (
    typeof slot !== "bigint" ||
    slot < (config.minContextSlot ?? 0n) ||
    slot > 0xffff_ffff_ffff_ffffn
  ) {
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
  if (typeof slot !== "bigint" || slot < minContextSlot || slot > 0xffff_ffff_ffff_ffffn)
    throw invalid("context.slot");
  return decodeBatch(
    result["value"],
    signatures.length,
    (entry) => {
      if (entry === null) return false;
      const status = decode.record(entry, "value");
      const landed = status["slot"];
      if (typeof landed !== "bigint" || landed < 0n || landed > slot) throw invalid("value.slot");
      const finality = status["confirmationStatus"];
      if (
        finality !== null &&
        finality !== "processed" &&
        finality !== "confirmed" &&
        finality !== "finalized"
      )
        throw invalid("value.confirmationStatus");
      const error = status["err"];
      if (error === null) return true;
      if (typeof error !== "string") decode.record(error, "value.err");
      else if (error.length === 0) throw invalid("value.err");
      return finality !== "finalized";
    },
    () => invalid("value"),
  );
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
