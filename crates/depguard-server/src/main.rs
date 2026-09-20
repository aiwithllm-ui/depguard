use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let bind = std::env::var("DEPGUARD_SERVER_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let pool = depguard_server::connect(&database_url).await?;
    depguard_server::migrate(&pool).await?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "DepGuard network server listening");
    axum::serve(listener, depguard_server::router(pool)).await?;
    Ok(())
}
