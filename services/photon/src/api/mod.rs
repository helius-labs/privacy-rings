pub mod error;
pub mod method;
pub mod root_index_cache;
pub mod rpc_server;
pub mod service;

use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction,
    IsolationLevel, TransactionTrait,
};

/// Begin a read transaction with `REPEATABLE READ` + `READ ONLY` on Postgres.
/// In test environments, `PHOTON_SKIP_ISOLATION_LEVEL` disables the isolation
/// level override to avoid read-after-write visibility issues.
pub async fn begin_read_transaction(
    conn: &DatabaseConnection,
) -> Result<DatabaseTransaction, sea_orm::DbErr> {
    if conn.get_database_backend() == DatabaseBackend::Postgres
        && std::env::var("PHOTON_SKIP_ISOLATION_LEVEL").is_err()
    {
        conn.begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await
    } else {
        conn.begin().await
    }
}
