# User registry

The registry maps a Solana owner address to its public shielded payment keys
and chosen merge scheme. The program ID and PDA derivation are defined in the
[registry interface](../program-libs/user-registry-interface/src/lib.rs).

The canonical record PDA uses the seeds ["zolana/registry/v0", owner].
The program owns initialized records and stores the owner and canonical bump
in each record. The [record type](../program-libs/user-registry-interface/src/state.rs)
defines its binary layout and merge schemes. An empty system-owned PDA counts
as uninitialized even when it holds lamports.

## Instructions

The [instruction interface](../program-libs/user-registry-interface/src/instruction.rs)
defines the discriminator, Borsh payload, and account list for each instruction.

| Instruction | Signers | Effect |
| --- | --- | --- |
| Register | Owner and payer | Initializes the canonical record. The payer supplies any missing rent and may also be the owner. The record starts with merging disabled. |
| Set merge encryption | Owner | Changes the merge scheme. |
| Update keys | Owner | Replaces the viewing key. The nullifier key is fixed at registration. |
| Assert payment targets | None | Checks the selected recipient states during payment execution. |

The program stores the public key bytes supplied by the owner. Wallets validate
the payment keys before use. The registry has no instruction that closes a record.

## Assert payment targets

The wallet derives one canonical record PDA per resolved owner and includes
them as signed account addresses in payment order. The instruction data after
the discriminator is one SHA-256 digest. Its input is
`spr/user-registry/payment-targets/v1` followed in account order by each PDA
address, one byte for key presence, and both keys when present.

The program reconstructs the digest from the named accounts. For an initialized
record it checks program ownership, the PDA derived from the stored owner and
bump, and the two payment keys. An uninitialized account must be empty and
system-owned. For an uninitialized record the signed PDA address establishes
which account to check. The merge scheme has no effect on the digest.

Append the assertion after the payment and any other instructions in the
same transaction. Solana locks the record against concurrent writes while the
transaction executes and rolls back the payment if the assertion fails. Use
this on the confidential default ring, where the output already names the
recipient. An anonymous policy-ring payment would disclose its recipient by
including this instruction. The wallet checks service policy separately.

Guarded wallet builders include one assertion covering all resolved owners.
These payments require a network running the updated registry program.

[Program tests](../program-tests/user-registry/tests/payment_target.rs) ·
[Wallet localnet tests](../sdk-libs/ts/test/e2e/private-flow.live.test.ts)
