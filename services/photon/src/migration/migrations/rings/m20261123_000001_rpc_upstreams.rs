use sea_orm_migration::prelude::*;

use super::super::super::model::table::RpcUpstreams;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Only an operator sets `approved_url`, a row without it routes no call.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RpcUpstreams::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RpcUpstreams::Pubkey)
                            .binary_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RpcUpstreams::Url).text().not_null())
                    .col(ColumnDef::new(RpcUpstreams::Methods).text().not_null())
                    .col(
                        ColumnDef::new(RpcUpstreams::AnnouncedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RpcUpstreams::ApprovedUrl).text())
                    .col(
                        ColumnDef::new(RpcUpstreams::ApprovalOrder)
                            .big_integer()
                            .unique_key(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RpcUpstreams::Table).to_owned())
            .await
    }
}
