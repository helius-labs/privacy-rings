use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

use super::super::super::model::table::RingsTxNullifiers;

/// Restrict the `(nullifier_tree, input_queue_seq)` uniqueness to queued
/// nullifiers.
///
/// A transact with a payer-funded circuit queues none of its nullifiers: each
/// input gets a permanent nullifier PDA instead. Its rows still record the spend
/// but carry the `NOT_QUEUED_INPUT_QUEUE_SEQ` sentinel (-1), which every queue
/// reader excludes with its non-negative `input_queue_seq >= start` filter. Many
/// such rows share the sentinel within one tree, so the unique index must only
/// cover non-negative sequences. Partial indexes have the same syntax on
/// Postgres and SQLite.
///
/// The partial index takes a new name: SQLite migrations run without a
/// transaction on a connection pool, so a drop and a create of the same name may
/// run on two connections, and in WAL mode the second can still see the index
/// the first dropped.
#[derive(DeriveMigrationName)]
pub struct Migration;

const QUEUE_SEQ_INDEX: &str = "idx_rings_tx_nullifiers_tree_queue_seq";
const QUEUED_SEQ_INDEX: &str = "idx_rings_tx_nullifiers_tree_queued_seq";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {QUEUED_SEQ_INDEX} ON rings_tx_nullifiers \
                 (nullifier_tree, input_queue_seq) WHERE input_queue_seq >= 0"
            ))
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name(QUEUE_SEQ_INDEX)
                    .table(RingsTxNullifiers::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The full index admits one row per sequence, so give every unqueued
        // row its own negative sequence first. Queue readers still skip them.
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE rings_tx_nullifiers SET input_queue_seq = -nullifier_id \
                 WHERE input_queue_seq < 0",
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(QUEUE_SEQ_INDEX)
                    .table(RingsTxNullifiers::Table)
                    .col(RingsTxNullifiers::NullifierTree)
                    .col(RingsTxNullifiers::InputQueueSeq)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name(QUEUED_SEQ_INDEX)
                    .table(RingsTxNullifiers::Table)
                    .to_owned(),
            )
            .await
    }
}
