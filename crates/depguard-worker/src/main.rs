//! The MVP derives aggregates synchronously at ingest. This worker is an
//! intentionally small future boundary for rebuilding SQL-derived projections.
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = depguard_server::connect(&database_url).await?;
    depguard_server::migrate(&pool).await?;
    depguard_server::rebuild_aggregates(&pool).await?;
    Ok(())
}
