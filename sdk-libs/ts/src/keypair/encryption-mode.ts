import { KeypairError } from "./error.js";

/** Per-output cipher selection, matching Rust `EncryptionMode`. */
export const EncryptionMode = Object.freeze({
  Hkdf: "hkdf",
  PoseidonKdf: "poseidonKdf",
} as const);
export type EncryptionMode = (typeof EncryptionMode)[keyof typeof EncryptionMode];

/** @internal Runtime validation for structural requests and JavaScript callers. */
export function checkedEncryptionMode(mode: unknown): EncryptionMode {
  switch (mode) {
    case EncryptionMode.Hkdf:
    case EncryptionMode.PoseidonKdf:
      return mode;
    default:
      throw new KeypairError("KEYPAIR_INVALID_ENCRYPTION_MODE");
  }
}
