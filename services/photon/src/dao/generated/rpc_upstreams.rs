use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "rpc_upstreams")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "VarBinary(StringLen::None)"
    )]
    pub pubkey: Vec<u8>,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    /// JSON array of method names.
    #[sea_orm(column_type = "Text")]
    pub methods: String,
    pub announced_at: i64,
    #[sea_orm(column_type = "Text", nullable)]
    pub approved_url: Option<String>,
    pub approved_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
