import { ShieldedKeypair, SigningKey, initializePoseidon } from "@heliuslabs/spr";
import { getTreeAddress } from "@heliuslabs/spr/addresses";
import { DepositAsset, getDepositInstructionAsync } from "@heliuslabs/spr/instructions";

/** Run in a Hermes consumer after installing its platform globals. */
export async function checkHermesDeposit() {
  if (typeof globalThis.HermesInternal === "undefined" || typeof WebAssembly !== "undefined") {
    throw new Error("The deposit test requires Hermes without WebAssembly");
  }

  await initializePoseidon();
  const seed = new Uint8Array(32);
  seed[31] = 1;
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
  seed.fill(0);
  try {
    const identity = keypair.shieldedAddress();
    const instruction = await getDepositInstructionAsync({
      tree: getTreeAddress(0),
      depositor: identity.solanaAddress(),
      deposits: [
        {
          asset: DepositAsset.sol(),
          viewTag: identity.confidentialViewTag(),
          recipientOwnerHash: identity.ownerHash(),
          amount: 42n,
        },
      ],
    });
    // The owner hash is pinned by test-vectors/key_derivation.json.
    const ownerHash = Uint8Array.from(
      "1095ab4e1b59e42e4be89f49210af7f42ed3d7d9c45065afcce69a9c5a877e36".match(/../g),
      (pair) => Number.parseInt(pair, 16),
    );
    const { data } = instruction;
    const found = data.some((_, start) =>
      ownerHash.every((byte, offset) => data[start + offset] === byte),
    );
    if (!found) throw new Error("Deposit instruction has the wrong owner hash");
  } finally {
    keypair.destroy();
  }
}
