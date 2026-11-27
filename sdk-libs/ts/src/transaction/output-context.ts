import { treeAddress } from "../interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../interface/tree-slot.js";
import type { Address } from "../interface/types.js";

import { TransactionError } from "./error.js";
import { checkedTreeId } from "./utxo.js";

/** @internal Resolve legacy default-tree contexts without guessing other tree ids. */
export function outputContextTreeId(context: Readonly<{ tree: Address; treeId?: number }>): number {
  if (context.treeId === undefined) {
    if (context.tree !== treeAddress(DEFAULT_TREE_ID)) {
      throw new TransactionError("TRANSACTION_MISSING_TREE_ID");
    }
    return DEFAULT_TREE_ID;
  }
  const treeId = checkedTreeId(context.treeId);
  if (context.tree !== treeAddress(treeId)) {
    throw new TransactionError("TRANSACTION_OUTPUT_TREE_MISMATCH");
  }
  return treeId;
}
