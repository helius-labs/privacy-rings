/** Experimental opt-in fetch adapter. No global fetch replacement or automatic fallback. */
const INDEXER = new Set([
  "getEncryptedUtxosByTags",
  "getShieldedTransactionsByTags",
  "getShieldedTransactionsBySignature",
  "getShieldedTransactionsByNullifiers",
  "getMerkleProofs",
  "getNonInclusionProofs",
  "getUserRecords",
]);
const WALLET = new Map([
  ["/v1/private-wallet/session", "privateWalletSession"],
  ["/v1/private-wallet/enroll", "privateWalletEnroll"],
  ["/v1/private-wallet/operations", "privateWalletOperations"],
  ["/v1/decryption/session", "decryptionSession"],
  ["/v1/decryption/operations", "decryptionOperations"],
]);
const MAX_BYTES = 12 * 1024 * 1024;
const HEX = /^(?:[0-9a-f]{2})*$/;
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const refuse = () => {
  throw new Error("Invalid root RPC prototype transport data");
};
const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
function unhex(value) {
  if (
    typeof value !== "string" ||
    !HEX.test(value) ||
    value.length > MAX_BYTES * 2
  )
    refuse();
  return Uint8Array.from(value.match(/../g) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
}
async function bounded(body) {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_BYTES) {
        await reader.cancel();
        refuse();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
function parse(bytes) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    refuse();
  }
}
function query(url, allowed) {
  for (const name of url.searchParams.keys())
    if (!["api-key", ...allowed].includes(name)) refuse();
  for (const name of ["api-key", ...allowed])
    if (url.searchParams.getAll(name).length > 1) refuse();
}
function endpointUrl(input) {
  const url = new URL(input);
  if (
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)
      )) ||
    url.username ||
    url.password ||
    url.hash ||
    url.pathname !== "/"
  )
    refuse();
  query(url, []);
  return url;
}

/**
 * Inject as `SprClient`'s `fetch`, or as `{ fetch: rootFetch }` in the TVC
 * gateway/prover transport. Keep the SDK's existing configured service URLs.
 * Only recognized legacy SPR routes on legacyOrigin are translated.
 */
export function createRootRpcFetch({
  endpoint,
  legacyOrigin,
  fetch: send = globalThis.fetch,
}) {
  const root = endpointUrl(endpoint);
  const origin =
    legacyOrigin === undefined ? root.origin : endpointUrl(legacyOrigin).origin;
  let sequence = 0;
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input);
    if (
      url.origin !== origin ||
      !/^\/v1\/(?:spr|private-wallet|decryption)\//.test(url.pathname)
    ) {
      return send(input, init);
    }
    const request = new Request(input, init);
    const path = url.pathname.replace(/\/$/, "");
    let method,
      params,
      indexer = false,
      encrypted = false;
    const proof =
      /^\/v1\/spr\/prove\/([a-z0-9_]{1,128})(\/indexed|\/status)?$/.exec(path);
    const indexerMethod = path.slice("/v1/spr/".length);
    if (INDEXER.has(indexerMethod) && request.method === "POST") {
      query(url, []);
      const body = parse(await bounded(request.body));
      if (
        !object(body) ||
        body.jsonrpc !== "2.0" ||
        body.method !== indexerMethod ||
        body.id === undefined
      )
        refuse();
      method = body.method;
      params = body.params;
      indexer = body;
    } else if (proof && proof[2] !== "/status" && request.method === "POST") {
      query(url, []);
      if (
        request.headers.get("spr-tee") !== "v1" ||
        request.headers.has("x-async")
      )
        refuse();
      const enc = request.headers.get("spr-tee-enc");
      if (typeof enc !== "string" || enc.length !== 64 || !HEX.test(enc))
        refuse();
      method = "zolanaProve";
      encrypted = true;
      params = {
        provingKey: proof[1],
        indexed: proof[2] === "/indexed",
        encryptedRequest: {
          version: "v1",
          enc,
          ciphertext: hex(await bounded(request.body)),
        },
      };
    } else if (proof?.[2] === "/status" && request.method === "GET") {
      query(url, ["jobId"]);
      if (request.headers.has("spr-tee") || !url.searchParams.get("jobId"))
        refuse();
      method = "zolanaProveStatus";
      params = { provingKey: proof[1], jobId: url.searchParams.get("jobId") };
    } else if (path === "/v1/spr/attestation" && request.method === "GET") {
      query(url, ["nonce"]);
      method = "sprProverAttestation";
      params = { nonce: url.searchParams.get("nonce") };
    } else if (path === "/v1/spr/proving-keys" && request.method === "GET") {
      query(url, []);
      method = "sprProvingKeys";
      params = {};
    } else if (WALLET.has(path) && request.method === "POST") {
      query(url, []);
      method = WALLET.get(path);
      params = parse(await bounded(request.body));
      if (!object(params)) refuse();
    } else {
      refuse();
    }

    const target = new URL(root);
    const apiKey = url.searchParams.get("api-key");
    if (apiKey !== null) {
      if (
        target.searchParams.has("api-key") &&
        target.searchParams.get("api-key") !== apiKey
      )
        refuse();
      target.searchParams.set("api-key", apiKey);
    }
    const id = indexer ? indexer.id : `spr-root-${++sequence}`;
    const body = JSON.stringify(
      indexer || { jsonrpc: "2.0", id, method, params },
    );
    if (new TextEncoder().encode(body).length > 3 * 1024 * 1024) refuse();
    const headers = new Headers(request.headers);
    for (const name of [
      "spr-tee",
      "spr-tee-enc",
      "spr-tee-ciphertext",
      "content-length",
      "content-encoding",
      "accept-encoding",
      "x-sync",
      "x-async",
    ])
      headers.delete(name);
    headers.set("content-type", "application/json");
    const response = await send(target, {
      method: "POST",
      headers,
      body,
      signal: request.signal,
      redirect: "error",
    });
    if (!response.ok) return response; // HTTP auth/rate-limit/transport failures retain their semantics.
    const value = parse(await bounded(response.body));
    if (
      !object(value) ||
      value.jsonrpc !== "2.0" ||
      value.id !== id ||
      Object.hasOwn(value, "result") === Object.hasOwn(value, "error")
    )
      refuse();
    const resultHeaders = new Headers(response.headers);
    for (const name of ["content-length", "content-encoding", "spr-tee"])
      resultHeaders.delete(name);
    resultHeaders.set("content-type", "application/json");
    if (indexer)
      return new Response(JSON.stringify(value), { headers: resultHeaders });
    if (Object.hasOwn(value, "error")) {
      const error = value.error;
      if (
        !object(error) ||
        error.code !== -32050 ||
        !object(error.data) ||
        !Number.isInteger(error.data.status) ||
        error.data.status < 400 ||
        error.data.status > 599
      )
        refuse();
      if (typeof error.data.retryAfter === "string")
        resultHeaders.set("retry-after", error.data.retryAfter);
      return new Response(JSON.stringify(error.data.body), {
        status: error.data.status,
        headers: resultHeaders,
      });
    }
    if (encrypted) {
      if (
        !object(value.result) ||
        value.result.version !== "v1" ||
        typeof value.result.ciphertext !== "string" ||
        value.result.ciphertext.length < 60
      )
        refuse();
      resultHeaders.set("spr-tee", "v1");
      resultHeaders.set("content-type", "application/octet-stream");
      return new Response(unhex(value.result.ciphertext), {
        headers: resultHeaders,
      });
    }
    return new Response(JSON.stringify(value.result), {
      headers: resultHeaders,
    });
  };
}
