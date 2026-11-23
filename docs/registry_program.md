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
| Assert payment target | None | Reads the canonical record during payment execution. |

The program stores the public key bytes supplied by the owner. Wallets validate
the payment keys before use. The registry has no instruction that closes a record.

## Assert payment target

The instruction reads one account, the canonical record PDA derived from the
recipient in the payload. Registered payments require a valid record with the
expected owner, bump, nullifier key, and viewing key. Service payments require
the record to remain uninitialized. The merge scheme has no effect on either check.

Append the assertion after the payment and any other instructions in the
same transaction. Solana locks the record against concurrent writes while the
transaction executes and rolls back the payment if the assertion fails. Use
this on the confidential default ring, where the output already names the
recipient. An anonymous policy-ring payment would disclose its recipient by
including this instruction. The wallet checks service policy separately.

The program change adds this instruction. Guarded wallet builders currently
check the registry before signing and broadcast. Execution-time enforcement
requires the builders to include the assertion and the network to run the
updated registry program.

[Execution tests](../program-tests/user-registry/tests/payment_target.rs)
