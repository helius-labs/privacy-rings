use super::{rings_output_leaf_indices, rings_outputs, PhotonApiError};
use sea_orm::{ConnectionTrait, Database, DbBackend, Schema, TransactionTrait};
use spr_indexer_api::{Hash, SerializablePubkey};

#[tokio::test]
async fn a_nonexistent_output_leaf_has_a_specific_rpc_reason() {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("database");
    let table = Schema::new(DbBackend::Sqlite).create_table_from_entity(rings_outputs::Entity);
    database
        .execute(DbBackend::Sqlite.build(&table))
        .await
        .expect("output table");
    let transaction = database.begin().await.expect("transaction");
    let failure = rings_output_leaf_indices(
        &transaction,
        SerializablePubkey::default(),
        &[Hash::from([1; 32])],
    )
    .await
    .expect_err("nonexistent output leaf");
    assert_eq!(failure, PhotonApiError::OutputLeafNotFound);
}
