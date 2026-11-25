use clap::{Parser, Subcommand};
use photon_indexer::upstreams::{self, Approve};
use sea_orm::{ConnectOptions, Database};
use solana_pubkey::Pubkey;
use spr_rpc_http::forward::UpstreamUrl;

/// Approves the JSON-RPC upstreams Photon forwards to.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short = 'u', long, env = "DATABASE_URL")]
    database_url: String,

    #[arg(short = 's', long, env = "DATABASE_SCHEMA", default_value = "public")]
    database_schema: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Every announced upstream, approved or pending.
    List,
    /// Route the upstream's methods to the URL it announced.
    Approve { pubkey: Pubkey, url: UpstreamUrl },
    /// Delete the upstream.
    Revoke { pubkey: Pubkey },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let options = ConnectOptions::new(args.database_url)
        .set_schema_search_path(args.database_schema)
        .to_owned();
    let db = Database::connect(options).await?;
    match args.command {
        Command::List => {
            for upstream in upstreams::list(&db).await? {
                let pubkey = Pubkey::try_from(upstream.pubkey.as_slice())?;
                let announced: UpstreamUrl = upstream.url.parse()?;
                let approved = match (upstream.approved_url, upstream.approved_methods) {
                    (Some(url), Some(methods)) => {
                        format!("{} {methods}", url.parse::<UpstreamUrl>()?)
                    }
                    _ => "pending".to_owned(),
                };
                println!(
                    "{pubkey}\tannounced {announced} {}\tapproved {approved}",
                    upstream.methods
                );
            }
        }
        Command::Approve { pubkey, url } => Approve { pubkey, url }.record(&db).await?,
        Command::Revoke { pubkey } => upstreams::revoke(&db, pubkey).await?,
    }
    Ok(())
}
