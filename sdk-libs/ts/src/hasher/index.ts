import { Field, type IField } from "@noble/curves/abstract/modular.js";
import {
  grainGenConstants,
  poseidon as createPermutation,
} from "@noble/curves/abstract/poseidon.js";

export type HasherFailureCode =
  | "NotInitialized"
  | "InvalidNumFields"
  | "InvalidInputLength"
  | "Poseidon";

/** @internal No barrel exports it. */
export class HasherFailure extends Error {
  readonly code: HasherFailureCode;

  constructor(code: HasherFailureCode, message: string) {
    super(message);
    this.name = "HasherFailure";
    this.code = code;
  }
}

const FIELD_BYTES = 32;

/** Every Poseidon input and output is below it. */
export const BN254_SCALAR_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** `a + b` in the BN254 scalar field, for the additive Poseidon-pad ciphers. */
export function fieldAdd(a: bigint, b: bigint): bigint {
  return (((a + b) % BN254_SCALAR_ORDER) + BN254_SCALAR_ORDER) % BN254_SCALAR_ORDER;
}

/** `a - b` in the BN254 scalar field. */
export function fieldSub(a: bigint, b: bigint): bigint {
  return (((a - b) % BN254_SCALAR_ORDER) + BN254_SCALAR_ORDER) % BN254_SCALAR_ORDER;
}

// Matches light-poseidon BN254 x^5 in state widths 2 through 13.
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65] as const;
/** The widest digest supported by both the runtime and the Solana verifier. */
export const MAX_POSEIDON_INPUTS = PARTIAL_ROUNDS.length;

const permutations = new Map<number, ReturnType<typeof createPermutation>>();
let field: IField<bigint> | undefined;

/** Initializes the scalar field. Each width is prepared the first time it is used. */
export function initializePoseidon(): Promise<void> {
  field ??= Field(BN254_SCALAR_ORDER);
  return Promise.resolve();
}

/** Whether `poseidon` can be called. */
export function isPoseidonInitialized(): boolean {
  return field !== undefined;
}

/** @internal Clears the field and cached permutations for initialization tests. */
export function resetPoseidonForTests(): void {
  field = undefined;
  permutations.clear();
}

/** Hashes one to twelve unsigned big-endian field elements. */
export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  const active = field;
  if (active === undefined) {
    throw new HasherFailure(
      "NotInitialized",
      "the Poseidon hasher is not initialized, await initializePoseidon() once before hashing",
    );
  }
  const roundsPartial = PARTIAL_ROUNDS[inputs.length - 1];
  if (roundsPartial === undefined) {
    throw new HasherFailure(
      "InvalidNumFields",
      `Poseidon takes 1 to ${String(MAX_POSEIDON_INPUTS)} inputs, received ${String(inputs.length)}`,
    );
  }

  const values = inputs.map((input, index) => {
    if (input.length > FIELD_BYTES) {
      throw new HasherFailure(
        "InvalidInputLength",
        `Poseidon input ${String(index)} is ${String(input.length)} bytes, the field takes 32`,
      );
    }
    let value = 0n;
    for (const byte of input) value = (value << 8n) | BigInt(byte);
    if (!active.isValid(value)) {
      throw new HasherFailure("Poseidon", "Poseidon input is outside the BN254 scalar field");
    }
    return value;
  });
  try {
    const t = values.length + 1;
    let permutation = permutations.get(t);
    if (permutation === undefined) {
      const options = { Fp: active, t, roundsFull: 8, roundsPartial, sboxPower: 5 };
      permutation = createPermutation({ ...options, ...grainGenConstants(options) });
      permutations.set(t, permutation);
    }
    const [digest] = permutation([0n, ...values]);
    if (digest !== undefined) return active.toBytes(digest);
  } catch {
    throw new HasherFailure("Poseidon", "Poseidon rejected the input");
  }
  throw new HasherFailure("Poseidon", "Poseidon returned no digest");
}

/** Packs fixed-size bytes into 31-byte fields and folds them like Rust `hash_bytes`. */
export function hashBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) return new Uint8Array(FIELD_BYTES);
  let offset = 0;
  let result = packed(bytes.subarray(0, 31));
  offset = 31;
  while (offset < bytes.length) {
    result = poseidon([result, packed(bytes.subarray(offset, offset + 31))]);
    offset += 31;
  }
  return result;
}

/** Algorithm tag of an Ed25519 or PDA owner identity, `'S'`. */
export const SOLANA_OWNER_TAG = 0x53;
/** Hashes the Solana owner tag with a fixed-width identity key. */
export function solanaOwnerIdentity(key: Uint8Array): Uint8Array {
  if (key.length !== FIELD_BYTES) {
    throw new HasherFailure(
      "InvalidInputLength",
      `an owner identity takes a 32-byte key, received ${String(key.length)} bytes`,
    );
  }
  const tagged = new Uint8Array(FIELD_BYTES + 1);
  tagged[0] = SOLANA_OWNER_TAG;
  tagged.set(key, 1);
  return hashBytes(tagged);
}

function packed(bytes: Uint8Array): Uint8Array {
  const field = new Uint8Array(FIELD_BYTES);
  field.set(bytes, FIELD_BYTES - bytes.length);
  return field;
}
