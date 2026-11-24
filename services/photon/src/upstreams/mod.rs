//! Registry of the JSON-RPC services Photon forwards to, each announced under
//! its key and approved by an operator.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use jsonrpsee::{
    server::{ServerBuilder, ServerHandle},
    types::{error::ErrorCode, ErrorObjectOwned},
    RpcModule,
};
use sea_orm::{
    sea_query::{Expr, Func, OnConflict, Query, SimpleExpr},
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
};
use solana_pubkey::Pubkey;
use spr_indexer_api::{
    method::AnnounceUpstream, AnnounceUpstreamRequest, AnnounceUpstreamResponse, RpcMethod,
};
use spr_rpc_http::forward::{UpstreamUrl, UpstreamUrlError};
use thiserror::Error;

use crate::dao::generated::rpc_upstreams::{ActiveModel, Column, Entity, Model};

pub const ANNOUNCEMENT_SKEW: Duration = Duration::from_secs(60);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error(transparent)]
    Url(#[from] UpstreamUrlError),
    #[error("`{0}` is not a method name")]
    MethodName(String),
    #[error("the announcement timestamp is outside the accepted skew")]
    Skew,
    #[error("the announcement signature does not verify")]
    Signature,
    #[error("the key has an announcement with this timestamp or a later one")]
    Superseded,
    #[error("the key did not announce the URL")]
    NotAnnounced,
    #[error("the key has no announcement")]
    Unknown,
    #[error("the registry address must be loopback or private")]
    PublicBind,
    #[error(transparent)]
    Stored(#[from] serde_json::Error),
    #[error(transparent)]
    Database(#[from] DbErr),
}

impl From<UpstreamError> for ErrorObjectOwned {
    fn from(error: UpstreamError) -> Self {
        match error {
            UpstreamError::Stored(_) | UpstreamError::Database(_) => {
                log::error!("upstream registry: {error}");
                ErrorCode::InternalError.into()
            }
            refusal => Self::owned(
                ErrorCode::InvalidParams.code(),
                refusal.to_string(),
                None::<()>,
            ),
        }
    }
}

/// An announcement with a verified signature, timestamp, URL and method names.
#[derive(Debug)]
pub struct Announced {
    pubkey: Pubkey,
    url: UpstreamUrl,
    methods: Vec<String>,
    timestamp: i64,
}

impl Announced {
    pub fn verify(request: AnnounceUpstreamRequest, now: u64) -> Result<Self, UpstreamError> {
        let AnnounceUpstreamRequest {
            pubkey,
            announcement,
            signature,
        } = request;
        VerifyingKey::from_bytes(&pubkey.0.to_bytes())
            .and_then(|key| {
                // Without the strict check a small-order key signs many messages at once.
                key.verify_strict(
                    &announcement.message(),
                    &Signature::from_bytes(&signature.0.into()),
                )
            })
            .map_err(|_| UpstreamError::Signature)?;
        if now.abs_diff(announcement.timestamp) > ANNOUNCEMENT_SKEW.as_secs() {
            return Err(UpstreamError::Skew);
        }
        if let Some(name) = announcement
            .methods
            .iter()
            .find(|name| !is_method_name(name))
        {
            return Err(UpstreamError::MethodName(name.clone()));
        }
        Ok(Self {
            pubkey: pubkey.0,
            url: announcement.url.parse()?,
            timestamp: i64::try_from(announcement.timestamp).map_err(|_| UpstreamError::Skew)?,
            methods: announcement.methods,
        })
    }

    /// Whether an operator approved the announced URL.
    pub async fn record(self, db: &DatabaseConnection) -> Result<bool, UpstreamError> {
        let pubkey = self.pubkey.to_bytes().to_vec();
        let row = ActiveModel {
            pubkey: Set(pubkey.clone()),
            url: Set(self.url.to_string()),
            methods: Set(serde_json::to_string(&self.methods)?),
            announced_at: Set(self.timestamp),
            approved_url: Set(None),
            approval_order: Set(None),
        };
        let written = Entity::insert(row)
            .on_conflict(
                OnConflict::column(Column::Pubkey)
                    .update_columns([Column::Url, Column::Methods, Column::AnnouncedAt])
                    // A replayed announcement cannot roll the methods back.
                    .action_and_where(Expr::col((Entity, Column::AnnouncedAt)).lt(self.timestamp))
                    .to_owned(),
            )
            .exec_without_returning(db)
            .await?;
        if written == 0 {
            return Err(UpstreamError::Superseded);
        }
        let approved = Entity::find_by_id(pubkey)
            .one(db)
            .await?
            .and_then(|row| row.approved_url);
        Ok(approved.as_deref() == Some(self.url.as_str()))
    }
}

fn is_method_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
}

/// Pins the URL the operator read, a later announcement cannot change it.
pub struct Approve {
    pub pubkey: Pubkey,
    pub url: UpstreamUrl,
}

impl Approve {
    pub async fn record(self, db: &DatabaseConnection) -> Result<(), UpstreamError> {
        let next = Query::select()
            .expr(
                Expr::expr(Func::coalesce([
                    Expr::col(Column::ApprovalOrder).max(),
                    Expr::value(0),
                ]))
                .add(1),
            )
            .from(Entity)
            .to_owned();
        let approved = Entity::update_many()
            .col_expr(Column::ApprovedUrl, Expr::value(self.url.as_str()))
            // The first approval keeps its place among upstreams naming one method.
            .col_expr(
                Column::ApprovalOrder,
                Func::coalesce([
                    Expr::col(Column::ApprovalOrder).into(),
                    SimpleExpr::SubQuery(None, Box::new(next.into_sub_query_statement())),
                ])
                .into(),
            )
            .filter(Column::Pubkey.eq(self.pubkey.to_bytes().to_vec()))
            .filter(Column::Url.eq(self.url.as_str()))
            .exec(db)
            .await?;
        match approved.rows_affected {
            0 => Err(UpstreamError::NotAnnounced),
            _ => Ok(()),
        }
    }
}

pub async fn revoke(db: &DatabaseConnection, pubkey: Pubkey) -> Result<(), UpstreamError> {
    let revoked = Entity::delete_by_id(pubkey.to_bytes().to_vec())
        .exec(db)
        .await?;
    match revoked.rows_affected {
        0 => Err(UpstreamError::Unknown),
        _ => Ok(()),
    }
}

pub async fn list(db: &DatabaseConnection) -> Result<Vec<Model>, UpstreamError> {
    Ok(Entity::find()
        .order_by_asc(Column::AnnouncedAt)
        .all(db)
        .await?)
}

/// Method name to approved upstream, as of the last refresh.
#[derive(Default)]
pub struct Routes(RwLock<HashMap<String, UpstreamUrl>>);

impl Routes {
    /// Returns after the first refresh, a restarted Photon routes its first call.
    pub async fn spawn(db: Arc<DatabaseConnection>) -> Result<Arc<Self>, UpstreamError> {
        let routes = Arc::new(Self::default());
        routes.refresh(&db).await?;
        let refreshed = routes.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                if let Err(error) = refreshed.refresh(&db).await {
                    log::warn!("upstream routes: {error}");
                }
            }
        });
        Ok(routes)
    }

    pub async fn refresh(&self, db: &DatabaseConnection) -> Result<(), UpstreamError> {
        let approved = Entity::find()
            .filter(Column::ApprovedUrl.is_not_null())
            .order_by_asc(Column::ApprovalOrder)
            .all(db)
            .await?;
        let mut routes = HashMap::new();
        for row in approved {
            let Some(url) = row.approved_url else {
                continue;
            };
            let url: UpstreamUrl = url.parse()?;
            for method in serde_json::from_str::<Vec<String>>(&row.methods)? {
                routes.entry(method).or_insert_with(|| url.clone());
            }
        }
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = routes;
        Ok(())
    }

    pub fn get(&self, method: &str) -> Option<UpstreamUrl> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(method)
            .cloned()
    }
}

/// Any key may write a pending row, the address must be loopback or private.
pub async fn serve_registry(
    db: Arc<DatabaseConnection>,
    address: SocketAddr,
) -> anyhow::Result<(SocketAddr, ServerHandle)> {
    if !is_private(address.ip()) {
        return Err(UpstreamError::PublicBind.into());
    }
    let mut module = RpcModule::new(db);
    module.register_async_method(AnnounceUpstream::NAME, |params, db, _| async move {
        let approved = Announced::verify(params.parse()?, unix_now())?
            .record(&db)
            .await?;
        Ok::<_, ErrorObjectOwned>(AnnounceUpstreamResponse { approved })
    })?;
    let server = ServerBuilder::default().build(address).await?;
    Ok((server.local_addr()?, server.start(module)))
}

fn is_private(ip: IpAddr) -> bool {
    ip.is_loopback()
        || match ip {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => ip.is_unique_local(),
        }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sea_orm::Database;
    use spr_indexer_api::UpstreamAnnouncement;

    use super::*;
    use crate::migration::{MigratorTrait, RingsMigrator};

    pub(crate) const NOW: u64 = 1_800_000_000;

    pub(crate) async fn database() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        db
    }

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn pubkey(key: &SigningKey) -> Pubkey {
        Pubkey::from(key.verifying_key().to_bytes())
    }

    pub(crate) fn signed(
        key: &SigningKey,
        url: &str,
        methods: &[&str],
        timestamp: u64,
    ) -> AnnounceUpstreamRequest {
        let announcement = UpstreamAnnouncement {
            url: url.to_owned(),
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            timestamp,
        };
        AnnounceUpstreamRequest {
            pubkey: pubkey(key).into(),
            signature: solana_signature::Signature::from(
                key.sign(&announcement.message()).to_bytes(),
            )
            .into(),
            announcement,
        }
    }

    #[test]
    fn an_announcement_needs_its_key_signature_a_current_clock_and_plain_method_names() {
        let key = key(1);
        let valid = || signed(&key, "http://ring:8785", &["ringStatus"], NOW);
        assert!(Announced::verify(valid(), NOW).is_ok());

        let mut other_url = valid();
        other_url.announcement.url = "http://attacker".to_owned();
        let mut other_methods = valid();
        other_methods.announcement.methods.push("health".to_owned());
        let mut other_key = valid();
        other_key.pubkey = pubkey(&super::tests::key(2)).into();
        for forged in [other_url, other_methods, other_key] {
            assert!(matches!(
                Announced::verify(forged, NOW),
                Err(UpstreamError::Signature)
            ));
        }

        for now in [NOW - 61, NOW + 61] {
            assert!(matches!(
                Announced::verify(valid(), now),
                Err(UpstreamError::Skew)
            ));
        }
        for name in ["", "ring status", "ring/status", "ringStatus\n"] {
            let request = signed(&key, "http://ring:8785", &[name], NOW);
            assert!(matches!(
                Announced::verify(request, NOW),
                Err(UpstreamError::MethodName(_))
            ));
        }
        let request = signed(&key, "http://ring:8785/?key=1", &["ringStatus"], NOW);
        assert!(matches!(
            Announced::verify(request, NOW),
            Err(UpstreamError::Url(_))
        ));
    }

    #[tokio::test]
    async fn a_replayed_announcement_cannot_replace_a_later_one() {
        let db = database().await;
        let key = key(1);
        let announce = |methods: &'static [&'static str], timestamp| {
            Announced::verify(
                signed(&key, "http://ring:8785", methods, timestamp),
                timestamp,
            )
            .unwrap()
        };
        assert!(!announce(&["ringStatus", "submitRelay"], NOW)
            .record(&db)
            .await
            .unwrap());
        announce(&["ringStatus"], NOW + 1)
            .record(&db)
            .await
            .unwrap();
        for replayed in [NOW, NOW + 1] {
            assert!(matches!(
                announce(&["ringStatus", "submitRelay"], replayed)
                    .record(&db)
                    .await,
                Err(UpstreamError::Superseded)
            ));
        }
        assert_eq!(list(&db).await.unwrap()[0].methods, r#"["ringStatus"]"#);
    }

    #[tokio::test]
    async fn an_approval_pins_the_announced_url_and_the_first_approval_keeps_a_method() {
        let db = database().await;
        // The first approved key sorts last, only the approval order ranks them.
        let mut keys = [key(1), key(2)];
        keys.sort_by_key(|key| std::cmp::Reverse(pubkey(key).to_bytes()));
        let [first, second] = keys;
        let announce = |key: &SigningKey, url: &str, timestamp| {
            Announced::verify(signed(key, url, &["ringStatus"], timestamp), timestamp).unwrap()
        };
        let approve = |key: &SigningKey, url: &str| Approve {
            pubkey: pubkey(key),
            url: url.parse().unwrap(),
        };
        let routes = Routes::default();
        let routed = |routes: &Routes| routes.get("ringStatus").map(|url| url.to_string());

        announce(&first, "http://first", NOW)
            .record(&db)
            .await
            .unwrap();
        announce(&second, "http://second", NOW)
            .record(&db)
            .await
            .unwrap();
        routes.refresh(&db).await.unwrap();
        assert_eq!(routed(&routes), None);

        assert!(matches!(
            approve(&first, "http://other").record(&db).await,
            Err(UpstreamError::NotAnnounced)
        ));
        approve(&first, "http://first").record(&db).await.unwrap();
        approve(&second, "http://second").record(&db).await.unwrap();
        approve(&first, "http://first").record(&db).await.unwrap();
        routes.refresh(&db).await.unwrap();
        assert_eq!(routed(&routes).as_deref(), Some("http://first"));

        assert!(!announce(&first, "http://moved", NOW + 1)
            .record(&db)
            .await
            .unwrap());
        routes.refresh(&db).await.unwrap();
        assert_eq!(routed(&routes).as_deref(), Some("http://first"));

        revoke(&db, pubkey(&first)).await.unwrap();
        routes.refresh(&db).await.unwrap();
        assert_eq!(routed(&routes).as_deref(), Some("http://second"));
        assert!(matches!(
            revoke(&db, pubkey(&first)).await,
            Err(UpstreamError::Unknown)
        ));
    }

    #[tokio::test]
    async fn an_announcer_is_pending_until_an_operator_approves_its_url() {
        use spr_rpc_http::announce::Announcer;

        let db = Arc::new(database().await);
        let (address, registry) = serve_registry(db.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let key = key(1);
        let announcer = Announcer {
            registry: format!("http://{address}").parse().unwrap(),
            url: "http://ring:8785".parse().unwrap(),
            methods: vec!["ringStatus".to_owned()],
            pubkey: pubkey(&key),
        };
        let http = reqwest::Client::new();
        let sign = |message: &[u8]| solana_signature::Signature::from(key.sign(message).to_bytes());
        assert!(!announcer.announce(&http, &sign).await.unwrap());

        Approve {
            pubkey: announcer.pubkey,
            url: announcer.url.clone(),
        }
        .record(&db)
        .await
        .unwrap();
        // One second, an announcement must be later than the recorded one.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(announcer.announce(&http, &sign).await.unwrap());

        let forged = |_: &[u8]| solana_signature::Signature::from([7; 64]);
        assert!(announcer.announce(&http, &forged).await.is_err());
        registry.stop().unwrap();
    }

    #[tokio::test]
    async fn the_registry_refuses_a_public_address() {
        let db = Arc::new(database().await);
        for public in ["0.0.0.0:0", "8.8.8.8:0", "[2001:db8::1]:0"] {
            let error = serve_registry(db.clone(), public.parse().unwrap())
                .await
                .unwrap_err();
            assert!(
                matches!(error.downcast_ref(), Some(UpstreamError::PublicBind)),
                "{public}"
            );
        }
    }
}
