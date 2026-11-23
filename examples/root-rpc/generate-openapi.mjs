import { writeFile } from "node:fs/promises";

const indexer = [
  "getEncryptedUtxosByTags",
  "getShieldedTransactionsByTags",
  "getShieldedTransactionsBySignature",
  "getShieldedTransactionsByNullifiers",
  "getMerkleProofs",
  "getNonInclusionProofs",
  "getUserRecords",
];
const wallet = [
  "privateWalletSession",
  "privateWalletEnroll",
  "privateWalletOperations",
  "decryptionSession",
  "decryptionOperations",
];
const key = { type: "string", pattern: "^[a-z0-9_]{1,128}$" };
const closed = (properties, required = Object.keys(properties)) => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});
const hex = { type: "string", pattern: "^(?:[0-9a-f]{2})+$" };
const request = (method, params) =>
  closed({
    jsonrpc: { const: "2.0" },
    id: { type: ["string", "number", "null"] },
    method: { const: method },
    params,
  });
const schemas = indexer.map((method) => ({
  $ref: `../../services/photon/src/openapi/specs/rings.yaml#/paths/~1${method}/post/requestBody/content/application~1json/schema`,
}));
schemas.push(
  request(
    "zolanaProve",
    closed(
      {
        provingKey: key,
        indexed: { type: "boolean", default: false },
        encryptedRequest: closed({
          version: { const: "v1" },
          enc: { ...hex, minLength: 64, maxLength: 64 },
          ciphertext: { ...hex, minLength: 32 },
        }),
      },
      ["provingKey", "encryptedRequest"],
    ),
  ),
  request(
    "zolanaProveStatus",
    closed({
      provingKey: key,
      jobId: { type: "string", minLength: 1, maxLength: 256 },
    }),
  ),
  request(
    "sprProverAttestation",
    closed({ nonce: { ...hex, minLength: 64, maxLength: 64 } }),
  ),
  request("sprProvingKeys", closed({})),
  ...wallet.map((method) =>
    request(method, {
      type: "object",
      description:
        "Existing tvc-gateway request payload, including unchanged encrypted fields; validated by its existing handler.",
    }),
  ),
);
const doc = {
  openapi: "3.1.0",
  info: {
    title: "SPR root JSON-RPC facade prototype",
    version: "0.0.0-prototype",
    description:
      "Experimental; requires the gateway spr-root-rpc-prototype feature. Existing REST endpoints remain supported. This file describes the facade, not a deployed API. Batch arrays use the same item schemas; existing gateway batch limits apply.",
  },
  servers: [{ url: "http://127.0.0.1:8080" }],
  security: [{ apiKey: [] }],
  paths: {
    "/": {
      post: {
        operationId: "sprRpc",
        summary: "Dispatch SPR calls by JSON-RPC method",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                oneOf: [
                  { oneOf: schemas },
                  {
                    type: "array",
                    minItems: 1,
                    maxItems: 100,
                    items: { oneOf: schemas },
                  },
                ],
              },
            },
          },
        },
        responses: {
          200: {
            description:
              'JSON-RPC response (or batch). Indexer envelopes pass through; wallet/discovery values are returned as result. Encrypted proof result is {version: "v1", ciphertext: <hex>}, including authenticated inner failures. Upstream refusals use error -32050 with data.status, data.body and data.retryAfter.',
          },
          "4XX": {
            description:
              "Existing gateway authentication, access-control, size or admission rejection.",
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      apiKey: { type: "apiKey", in: "query", name: "api-key" },
    },
  },
};
await writeFile(
  new URL("./openapi.json", import.meta.url),
  JSON.stringify(doc, null, 2) + "\n",
);
