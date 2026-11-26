import { type Bytes32, checkedBytes, fieldU32 } from "../bytes.js";
import {
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOMAIN_MERGE_OUTPUT_CIPHERTEXT,
  DOMAIN_MERGE_OUTPUT_KEY,
} from "../derivation.js";
import { invalidLength } from "../error.js";
import type { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";
import { privateTxBlinding } from "../transact/index.js";
import { bytesToBigInt, rightAlign } from "../../interface/bytes.js";

export function mergeOutputBlinding(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_OUTPUT_BLINDING_V1),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

/**
 * The per-merge key of the output ciphertext, `Poseidon("TMOK",
 * nullifier_secret, first_nullifier)`: separated by the first nullifier so no
 * two merges share a key. Mirrors Rust `merge_output_key`.
 */
export function mergeOutputKey(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_OUTPUT_KEY),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

/** Field elements in a merge output ciphertext: the amount and two mint chunks. */
export const MERGE_OUTPUT_CIPHERTEXT_ELEMENTS = 3;

/**
 * The output ciphertext pads, `Poseidon("TMOC", key, salt, i)`: element `i`
 * of the plaintext is added to pad `i` in the BN254 scalar field. Mirrors Rust
 * `pads` in `instructions/merge/serialization.rs` and the circuit's `PoseidonCtr`.
 */
export function mergeOutputPads(key: Bytes32, salt: Uint8Array): readonly [bigint, bigint, bigint] {
  checkedBytes<Bytes32>(key, 32, "merge output key");
  if (salt.length !== 16) throw invalidLength("merge output salt", 16, salt.length);
  const alignedSalt = rightAlign(salt);
  const pad = (index: number): bigint =>
    bytesToBigInt(
      poseidon([fieldU32(DOMAIN_MERGE_OUTPUT_CIPHERTEXT), key, alignedSalt, fieldU32(index)]),
    );
  return [pad(0), pad(1), pad(2)];
}

/**
 * The private transaction blinding of a merge, `Poseidon("TXPB",
 * first_nullifier, nullifier_secret)`: merge has no blinding seed, the owner's
 * nullifier secret takes its place. Mirrors Rust `merge_private_tx_blinding`.
 */
export function mergePrivateTxBlinding(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return privateTxBlinding(checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"), secret);
  } finally {
    secret.fill(0);
  }
}

export function mergeDummyNullifier(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff) {
    throw new RangeError("merge dummy slot index must fit in u8");
  }
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
      fieldU32(slotIndex),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

function alignedNullifierSecret(nullifierKey: NullifierKey): Bytes32 {
  const secret = nullifierKey.secretBytes();
  try {
    return rightAlign(secret);
  } finally {
    secret.fill(0);
  }
}
