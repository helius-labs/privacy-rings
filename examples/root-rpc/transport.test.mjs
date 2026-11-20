import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createDecipheriv } from "node:crypto";
import { createRootRpcFetch } from "./transport.mjs";

const endpoint = "https://gateway.invalid/";
const base = "https://gateway.invalid/v1/spr";
const vectors = JSON.parse(
  await readFile(
    new URL("../../prover/tee/testdata/vectors.json", import.meta.url),
  ),
);
function fixture(result) {
  const calls = [];
  const fetch = createRootRpcFetch({
    endpoint,
    fetch: async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({ url: new URL(url), init, body });
      return Response.json({
        jsonrpc: "2.0",
        id: body.id,
        result: typeof result === "function" ? result(body) : result,
      });
    },
  });
  return { fetch, calls };
}
const proofInit = () => ({
  method: "POST",
  headers: {
    "spr-tee": "v1",
    "spr-tee-enc": vectors.enc,
    "content-type": "application/octet-stream",
    "x-sync": "true",
  },
  body: Buffer.from(vectors.ciphertext, "hex"),
});

test("encrypted prover vector crosses root RPC and its answer still decrypts", async () => {
  const { fetch, calls } = fixture({
    version: "v1",
    ciphertext: vectors.encrypted_response,
  });
  const response = await fetch(
    new URL(vectors.request_uri, "https://gateway.invalid"),
    proofInit(),
  );
  assert.equal(calls[0].url.pathname, "/");
  assert.equal(calls[0].url.searchParams.get("api-key"), "k");
  assert.equal(calls[0].body.method, "zolanaProve");
  assert.deepEqual(calls[0].body.params, {
    provingKey: "transfer_2_2",
    indexed: false,
    encryptedRequest: {
      version: "v1",
      enc: vectors.enc,
      ciphertext: vectors.ciphertext,
    },
  });
  assert.equal(calls[0].init.headers.has("spr-tee-enc"), false);
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(response.headers.get("spr-tee"), "v1");
  const encrypted = Buffer.from(await response.arrayBuffer());
  assert.equal(encrypted.toString("hex"), vectors.encrypted_response);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(vectors.response_key, "hex"),
    encrypted.subarray(0, 12),
  );
  decipher.setAuthTag(encrypted.subarray(-16));
  const decrypted = Buffer.concat([
    decipher.update(encrypted.subarray(12, -16)),
    decipher.final(),
  ]);
  assert.equal(decrypted.readUInt16BE(), vectors.response_status);
  assert.equal(decrypted.subarray(2).toString(), vectors.response_body);
});

test("indexer keeps its JSON-RPC envelope and correlates the original ID", async () => {
  const { fetch, calls } = fixture({ context: { slot: 7 }, value: [] });
  const response = await fetch(`${base}/getEncryptedUtxosByTags`, {
    method: "POST",
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 42,
      method: "getEncryptedUtxosByTags",
      params: { tags: [] },
    }),
  });
  assert.equal(calls[0].body.id, 42);
  assert.equal((await response.json()).id, 42);
  assert.deepEqual(calls[0].body.params, { tags: [] });
});

test("wallet and decryption operations keep encrypted bytes, evidence and replay metadata", async () => {
  for (const [path, method] of [
    ["private-wallet/operations", "privateWalletOperations"],
    ["decryption/operations", "decryptionOperations"],
  ]) {
    const result = {
      response: { ciphertext: "opaque-response" },
      bootProof: { publicKey: "sample" },
    };
    const { fetch, calls } = fixture(result);
    const params = {
      descriptor: { sample: true },
      request: { ciphertext: "opaque-request" },
    };
    const response = await fetch(`https://gateway.invalid/v1/${path}`, {
      method: "POST",
      body: JSON.stringify(params),
    });
    assert.equal(calls[0].body.method, method);
    assert.deepEqual(calls[0].body.params, params);
    assert.deepEqual(await response.json(), result);
  }
});

test("attestation, key catalog and queue polling use typed RPC params", async () => {
  const { fetch, calls } = fixture({ sample: true });
  await fetch(`${base}/attestation?nonce=${"ab".repeat(32)}`);
  await fetch(`${base}/proving-keys`);
  await fetch(`${base}/prove/sample_1_1/status?jobId=sample-job`);
  assert.deepEqual(
    calls.map((c) => c.body.method),
    ["sprProverAttestation", "sprProvingKeys", "zolanaProveStatus"],
  );
  assert.deepEqual(calls[2].body.params, {
    provingKey: "sample_1_1",
    jobId: "sample-job",
  });
});

test("key rotation and retry hints retain existing client behavior without transport retries", async () => {
  let count = 0;
  const fetch = createRootRpcFetch({
    endpoint,
    fetch: async (_url, init) => {
      count++;
      const r = JSON.parse(init.body);
      return Response.json({
        jsonrpc: "2.0",
        id: r.id,
        error: {
          code: -32050,
          message: "Upstream request refused",
          data: {
            status: 400,
            body: { code: "tee_decryption_failed" },
            retryAfter: "2",
          },
        },
      });
    },
  });
  const response = await fetch(`${base}/prove/sample_1_1`, proofInit());
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { code: "tee_decryption_failed" });
  assert.equal(response.headers.get("retry-after"), "2");
  assert.equal(count, 1);
});

test("unsupported paths, unauthenticated routing additions and plaintext proofs fail before network I/O", async () => {
  const { fetch, calls } = fixture({});
  for (const [url, init] of [
    [`${base}/prove/sample_1_1?extra=value`, proofInit()],
    [
      `${base}/prove/sample_1_1`,
      { method: "POST", body: '{"witness":"secret"}' },
    ],
    [`${base}/getNullifierQueueElements`, { method: "POST", body: "{}" }],
    [`${base}/attestation?nonce=a&nonce=b`, undefined],
    [
      `${base}/getEncryptedUtxosByTags`,
      { method: "POST", body: '{"jsonrpc":"2.0","id":1,"method":"other"}' },
    ],
  ])
    await assert.rejects(() => fetch(url, init), /Invalid root RPC/);
  assert.equal(calls.length, 0);
});

test("ordinary RPC and unrelated services pass through unchanged", async () => {
  const calls = [];
  const fetch = createRootRpcFetch({
    endpoint,
    fetch: async (input, init) => {
      calls.push({ input, init });
      return Response.json({ ok: true });
    },
  });
  const init = { method: "POST", body: '{"method":"sample"}' };
  await fetch(endpoint, init);
  await fetch("https://policy.invalid/network.json");
  assert.equal(calls[0].input, endpoint);
  assert.equal(calls[0].init, init);
  assert.equal(calls[1].input, "https://policy.invalid/network.json");
});

test("malformed IDs, missing encryption and unexpected RPC errors fail closed", async () => {
  for (const value of [
    { jsonrpc: "2.0", id: "wrong", result: {} },
    { jsonrpc: "2.0", result: {} },
    null,
  ]) {
    const fetch = createRootRpcFetch({
      endpoint,
      fetch: async () => Response.json(value),
    });
    await assert.rejects(
      () => fetch(`${base}/prove/sample_1_1`, proofInit()),
      /Invalid root RPC/,
    );
  }
  for (const result of [
    {},
    { version: "v1", ciphertext: "zz" },
    { version: "v2", ciphertext: "ab".repeat(32) },
  ]) {
    const { fetch } = fixture(result);
    await assert.rejects(
      () => fetch(`${base}/prove/sample_1_1`, proofInit()),
      /Invalid root RPC/,
    );
  }
});

test("abort signals propagate and conflicting credentials never dispatch", async () => {
  const controller = new AbortController();
  const { fetch, calls } = fixture({});
  await fetch(`${base}/proving-keys`, { signal: controller.signal });
  controller.abort();
  assert.equal(calls[0].init.signal.aborted, true);
  await assert.rejects(
    () => fetch(`${base}/proving-keys?api-key=a&api-key=b`),
    /Invalid root RPC/,
  );
  assert.equal(calls.length, 1);
});

test("passthrough does not consume a Request body", async () => {
  const request = new Request("https://policy.invalid/check", {
    method: "POST",
    body: "sample",
  });
  const fetch = createRootRpcFetch({
    endpoint,
    fetch: async (input) => Response.json({ body: await input.text() }),
  });
  assert.deepEqual(await (await fetch(request)).json(), { body: "sample" });
});

test("wire request limit includes hex expansion and response reads are bounded", async () => {
  const { fetch, calls } = fixture({});
  const init = proofInit();
  init.body = new Uint8Array(2 * 1024 * 1024);
  await assert.rejects(
    () => fetch(`${base}/prove/sample_1_1`, init),
    /Invalid root RPC/,
  );
  assert.equal(calls.length, 0);
  const oversized = createRootRpcFetch({
    endpoint,
    fetch: async () => new Response(new Uint8Array(12 * 1024 * 1024 + 1)),
  });
  await assert.rejects(
    () => oversized(`${base}/proving-keys`),
    /Invalid root RPC/,
  );
});

test("HTTP admission failures and idempotency headers survive", async () => {
  const denied = createRootRpcFetch({
    endpoint,
    fetch: async () =>
      new Response("limited", { status: 429, headers: { "retry-after": "5" } }),
  });
  const response = await denied(`${base}/proving-keys`);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "5");
  const fetch = createRootRpcFetch({
    endpoint,
    fetch: async (_url, init) =>
      Response.json(
        {
          jsonrpc: "2.0",
          id: JSON.parse(init.body).id,
          result: { response: {} },
        },
        { headers: { "idempotent-replayed": "true" } },
      ),
  });
  const replay = await fetch(
    "https://gateway.invalid/v1/private-wallet/operations",
    { method: "POST", body: "{}" },
  );
  assert.equal(replay.headers.get("idempotent-replayed"), "true");
});
