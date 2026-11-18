import type { Address, Bytes32, RequestContext } from "../../interface/types.js";
import type { Data } from "../data.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import type { Blinding } from "../utxo.js";

/** An opening counts only once core rebuilds its published commitment. */
export interface RingCodec {
  readonly ringProgramId: Address;
  open(
    event: IndexedShieldedTransaction,
    context?: RequestContext,
  ): Promise<readonly RingOpening[]>;
}

/** Owner, ring and published commitment come from core, never from the codec. */
export interface RingOpening {
  readonly slotIndex: number;
  /** The holder's key or `ZERO_NULLIFIER_PK`, core refuses any other. */
  readonly nullifierPublicKey: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Blinding;
  readonly data: Data;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}
