//! mhinapi is a REST API exposing My Hash Is Nice database over HTTP. It serves
//! mhinparser-produced SQLite statistics and queries a rollblock server for
//! UTXO balances.
mod cli;
mod config;
mod defaults;
mod rollblockpool;
mod routes;
mod sqlitepool;

use axum::Router;
use reqwest::Client;
use std::{path::PathBuf, time::Duration};
use tokio::net::TcpListener;

use crate::{
    cli::Cli,
    config::AppConfig,
    defaults::default_data_dir_path,
    rollblockpool::{build_rollblock_pool, ensure_rollblock_available, RollblockPool},
    routes::create_router,
    sqlitepool::{build_sqlite_pool, SqlitePool},
};

#[derive(Clone)]
pub struct AppState {
    pub sqlite_pool: SqlitePool,
    pub rollblock: RollblockPool,
    pub electr_url: String,
    pub http_client: Client,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("sqlite_pool", &"SqlitePool")
            .field("rollblock", &self.rollblock)
            .field("electr_url", &self.electr_url)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct BootstrapOverrides {
    pub sqlite_pool: Option<SqlitePool>,
    pub rollblock_pool: Option<RollblockPool>,
    pub http_client: Option<Client>,
}

#[derive(Debug)]
pub struct BootstrapOutput {
    pub state: AppState,
    pub router: Router,
    pub server_host: String,
    pub server_port: u16,
}

fn resolve_data_dir(config: &AppConfig) -> Result<PathBuf, String> {
    config
        .data_dir
        .clone()
        .or_else(default_data_dir_path)
        .ok_or_else(|| {
            "data_dir is required (set --data-dir, MHINAPI_DATA_DIR, or ensure the OS user data directory is available)".to_string()
        })
}

fn build_http_client() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("Failed to build HTTP client: {err}"))
}

async fn bootstrap(
    cli_args: Cli,
    overrides: BootstrapOverrides,
) -> Result<BootstrapOutput, String> {
    let config =
        AppConfig::load(&cli_args).map_err(|err| format!("Failed to load configuration: {err}"))?;

    let data_dir = resolve_data_dir(&config)?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|err| format!("Failed to create data directory {data_dir:?}: {err}"))?;

    let sqlite_path = data_dir.join("mhinstats.sqlite3");
    let sqlite_pool = match overrides.sqlite_pool {
        Some(pool) => pool,
        None => build_sqlite_pool(&sqlite_path)
            .map_err(|err| format!("Failed to build SQLite pool: {err}"))?,
    };

    let rollblock_pool = overrides.rollblock_pool.unwrap_or_else(|| {
        build_rollblock_pool(
            &config.rollblock_host,
            config.rollblock_port,
            &config.rollblock_user,
            &config.rollblock_password,
        )
    });
    ensure_rollblock_available(&rollblock_pool)
        .await
        .map_err(|err| format!("Rollblock server unavailable: {err}"))?;

    let http_client = match overrides.http_client {
        Some(client) => client,
        None => build_http_client()?,
    };

    let server_host = config.server_host;
    let server_port = config.server_port;

    let state = AppState {
        sqlite_pool,
        rollblock: rollblock_pool,
        electr_url: config.electr_url,
        http_client,
    };
    let router = create_router(state.clone());

    Ok(BootstrapOutput {
        state,
        router,
        server_host,
        server_port,
    })
}

#[tokio::main]
async fn main() {
    let cli_args = Cli::gather();

    match bootstrap(cli_args, BootstrapOverrides::default()).await {
        Ok(BootstrapOutput {
            router,
            server_host,
            server_port,
            ..
        }) => {
            let listener = TcpListener::bind((server_host.as_str(), server_port))
                .await
                .unwrap_or_else(|err| {
                    panic!("failed to bind listener on {server_host}:{server_port}: {err}")
                });
            println!(
                "mhinapi listening on http://{}",
                listener.local_addr().unwrap()
            );

            if let Err(err) = axum::serve(listener, router).await {
                eprintln!("server error: {err}");
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::Cli,
        rollblockpool::{build_rollblock_client_settings, MockRemoteStoreClient, RollblockPool},
    };
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn cli_with_data_dir(data_dir: PathBuf) -> Cli {
        Cli {
            config_file: None,
            data_dir: Some(data_dir),
            rollblock_host: Some("localhost".into()),
            rollblock_port: Some(9443),
            rollblock_user: Some("mhin".into()),
            rollblock_password: Some("mhin".into()),
            electr_url: Some("https://example.test/api".into()),
            server_host: Some("127.0.0.1".into()),
            server_port: Some(0),
        }
    }

    #[tokio::test]
    async fn bootstrap_fails_when_sqlite_missing() {
        let tmp = tempdir().expect("temp dir");
        let data_dir = tmp.path().join("missing");
        let cli = cli_with_data_dir(data_dir.clone());

        let err = bootstrap(cli, BootstrapOverrides::default())
            .await
            .expect_err("bootstrap should fail without sqlite file");

        assert!(
            err.contains("SQLite database not found"),
            "unexpected error: {err}"
        );
        assert!(
            data_dir.exists(),
            "bootstrap should create the data directory"
        );
    }

    #[tokio::test]
    async fn bootstrap_fails_when_rollblock_unavailable() {
        let tmp = tempdir().expect("temp dir");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let sqlite_path = data_dir.join("mhinstats.sqlite3");
        Connection::open(&sqlite_path).expect("create sqlite db");

        let cli = cli_with_data_dir(data_dir);

        let err = bootstrap(cli, BootstrapOverrides::default())
            .await
            .expect_err("rollblock without mock should fail in tests");

        assert!(
            err.contains("Rollblock server unavailable"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("mock client not configured"),
            "error should include mock connect failure: {err}"
        );
    }

    #[tokio::test]
    async fn bootstrap_succeeds_with_mock_rollblock() {
        let tmp = tempdir().expect("temp dir");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let sqlite_path = data_dir.join("mhinstats.sqlite3");
        Connection::open(&sqlite_path).expect("create sqlite db");

        let cli = cli_with_data_dir(data_dir.clone());

        let mock = MockRemoteStoreClient::new();
        let settings = build_rollblock_client_settings("mock", 1, "user", "pass");
        let rollblock_pool = RollblockPool::with_mock(settings, mock.clone());

        let output = bootstrap(
            cli,
            BootstrapOverrides {
                rollblock_pool: Some(rollblock_pool),
                ..Default::default()
            },
        )
        .await
        .expect("bootstrap should succeed with mock rollblock");

        assert!(
            mock.was_closed(),
            "mock client should be closed during availability check"
        );
        assert_eq!(output.state.electr_url, "https://example.test/api");
        assert_eq!(
            output.state.rollblock.settings().endpoint,
            "mock:1".to_string()
        );
        assert_eq!(output.state.rollblock.settings().user, "user");
        assert_eq!(output.state.rollblock.settings().password, "pass");
        assert_eq!(output.server_host, "127.0.0.1");
        assert_eq!(output.server_port, 0);
    }
}
