import { ctr } from "@noble/ciphers/aes.js";

import { type Bytes32, bigIntToBytes, checkedBytes, u32be } from "./bytes.js";
import {
  ENC_INFO_TRANSFER,
  ENC_INFO_POSEIDON_KDF,
  DOMAIN_POSEIDON_KDF_TRANSCRIPT,
  DOM_SEP_KEY,
  DOM_SEP_NONCE,
  DOM_SEP_SILO,
  HPKE_PREFIX,
  hkdfExpand,
  x25519Ecdh,
} from "./derivation.js";
import { EncryptionMode, checkedEncryptionMode } from "./encryption-mode.js";
import { invalidLength } from "./error.js";
import { poseidon } from "./poseidon.js";
import type { X25519PublicKey } from "./x25519.js";
import { concatBytes, rightAlign } from "../interface/bytes.js";

const encoder = new TextEncoder();

function keySchedule(
  sharedSecret: Uint8Array,
  info: Uint8Array,
): readonly [Uint8Array, Uint8Array] {
  const siloed = poseidon([bigIntToBytes(BigInt(DOM_SEP_SILO)), sharedSecret, rightAlign(info)]);
  let keyLow: Uint8Array | undefined;
  let keyHigh: Uint8Array | undefined;
  let nonceSource: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    keyLow = poseidon([bigIntToBytes(BigInt(DOM_SEP_KEY)), siloed]);
    keyHigh = poseidon([bigIntToBytes(BigInt(DOM_SEP_KEY) + 1n), siloed]);
    key = concatBytes(keyHigh.subarray(16), keyLow.subarray(16));
    nonceSource = poseidon([bigIntToBytes(BigInt(DOM_SEP_NONCE)), siloed]);
    const nonce = nonceSource.slice(20);
    const derivedKey = key;
    key = undefined;
    return [derivedKey, nonce];
  } finally {
    siloed.fill(0);
    keyLow?.fill(0);
    keyHigh?.fill(0);
    nonceSource?.fill(0);
    key?.fill(0);
  }
}

/** Poseidon key schedule and AES-256-CTR, matching Rust `symmetric_apply`. */
export function symmetricApply(
  sharedSecret: Uint8Array,
  info: Uint8Array,
  input: Uint8Array,
): Uint8Array {
  if (info.length !== 10) throw invalidLength("key schedule info", 10, info.length);
  const secret = checkedBytes<Bytes32>(sharedSecret, 32, "shared secret");
  let key: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  const counter = new Uint8Array(16);
  try {
    [key, nonce] = keySchedule(secret, info);
    counter.set(nonce);
    counter[15] = 2;
    return ctr(key, counter).encrypt(input);
  } finally {
    secret.fill(0);
    key?.fill(0);
    nonce?.fill(0);
    counter.fill(0);
  }
}

/** Fixed-size byte encodings are packed independently, matching Rust `pack_be`. */
function packKeyBytes(encoded: Uint8Array): Uint8Array[] {
  return [rightAlign(encoded.subarray(0, 31)), rightAlign(encoded.subarray(31))];
}

export function applyPoseidonKdfCipher(
  secret: Uint8Array,
  counterparty: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  input: Uint8Array,
  salt: Uint8Array,
  slotIndex: number,
): Uint8Array {
  const shared = x25519Ecdh(secret, counterparty);
  const sharedChunks = packKeyBytes(shared);
  let transcriptSecret: Uint8Array | undefined;
  try {
    transcriptSecret = poseidon([
      rightAlign(u32be(DOMAIN_POSEIDON_KDF_TRANSCRIPT)),
      ...sharedChunks,
      ...packKeyBytes(ephemeralPublicKey.toBytes()),
      ...packKeyBytes(recipientPublicKey.toBytes()),
      rightAlign(salt),
      rightAlign(u32be(slotIndex)),
    ]);
    return symmetricApply(transcriptSecret, ENC_INFO_POSEIDON_KDF, input);
  } finally {
    shared.fill(0);
    sharedChunks.forEach((chunk) => chunk.fill(0));
    transcriptSecret?.fill(0);
  }
}

export function applyUtxoCipher(
  mode: EncryptionMode,
  secret: Uint8Array,
  counterparty: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  input: Uint8Array,
  salt: Uint8Array,
  slotIndex: number,
): Uint8Array {
  switch (checkedEncryptionMode(mode)) {
    case EncryptionMode.Hkdf:
      return applyTransferCipher(
        secret,
        counterparty,
        ephemeralPublicKey,
        recipientPublicKey,
        input,
        salt,
        slotIndex,
      );
    case EncryptionMode.PoseidonKdf:
      return applyPoseidonKdfCipher(
        secret,
        counterparty,
        ephemeralPublicKey,
        recipientPublicKey,
        input,
        salt,
        slotIndex,
      );
  }
}

function deriveKeyNonce(
  dh: Uint8Array,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  salt: Uint8Array,
  slotIndex: number,
  infoLabel: string,
): readonly [Uint8Array, Uint8Array] {
  const ikm = concatBytes(dh, ephemeralPublicKey.toBytes(), recipientPublicKey.toBytes());
  const info = concatBytes(
    encoder.encode(HPKE_PREFIX),
    encoder.encode(infoLabel),
    salt,
    u32be(slotIndex),
  );
  try {
    const output = hkdfExpand(undefined, ikm, info, 44);
    return [output.subarray(0, 32), output.subarray(32)];
  } finally {
    ikm.fill(0);
  }
}

export function applyTransferCipher(
  secret: Uint8Array,
  counterparty: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  input: Uint8Array,
  salt: Uint8Array,
  slotIndex: number,
  infoLabel: string = ENC_INFO_TRANSFER,
): Uint8Array {
  // Every derived secret is wiped on the way out, including when HKDF or the
  // cipher throws: a rejected ciphertext must not leave the shared secret or
  // the AES key sitting in a live buffer.
  const shared = x25519Ecdh(secret, counterparty);
  let key: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  const counter = new Uint8Array(16);
  try {
    [key, nonce] = deriveKeyNonce(
      shared,
      ephemeralPublicKey,
      recipientPublicKey,
      salt,
      slotIndex,
      infoLabel,
    );
    counter.set(nonce);
    counter[15] = 2;
    return ctr(key, counter).encrypt(input);
  } finally {
    shared.fill(0);
    key?.fill(0);
    nonce?.fill(0);
    counter.fill(0);
  }
}
