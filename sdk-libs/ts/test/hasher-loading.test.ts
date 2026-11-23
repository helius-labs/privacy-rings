import { expect, it } from "vitest";

import {
  initializePoseidon,
  isPoseidonInitialized,
  poseidon,
  resetPoseidonForTests,
} from "../src/hasher/index.js";

it("initializes synchronous Poseidon when called concurrently", async () => {
  resetPoseidonForTests();

  try {
    expect(isPoseidonInitialized()).toBe(false);
    expect(() => poseidon([Uint8Array.of(0)])).toThrow(
      expect.objectContaining({ code: "NotInitialized" }),
    );
    await Promise.all([initializePoseidon(), initializePoseidon(), initializePoseidon()]);
    expect(isPoseidonInitialized()).toBe(true);
    expect(poseidon([Uint8Array.of(0)])).toHaveLength(32);
  } finally {
    resetPoseidonForTests();
    await initializePoseidon();
  }
});
