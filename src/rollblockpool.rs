//! Rollblock client pool for fetching UTXO balances.
//!
//! This module provides a thin wrapper around the rollblock client to simplify
//! connection management and enable mocking during tests.

use std::fmt;
#[cfg(test)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[cfg(not(test))]
use rollblock::client::{ClientConfig, RemoteStoreClient};
#[cfg(not(test))]
use rollblock::net::BasicAuthConfig;

#[derive(Clone)]
pub struct RollblockClientSettings {
    pub endpoint: String,
    pub user: String,
    pub password: String,
}

#[derive(Clone)]
pub struct RollblockPool {
    settings: RollblockClientSettings,
    #[cfg(test)]
    mock_client: Option<MockRemoteStoreClient>,
}

impl RollblockPool {
    pub fn new(settings: RollblockClientSettings) -> Self {
        Self {
            settings,
            #[cfg(test)]
            mock_client: None,
        }
    }

    #[cfg(test)]
    pub fn with_mock(
        settings: RollblockClientSettings,
        mock_client: MockRemoteStoreClient,
    ) -> Self {
        Self {
            settings,
            mock_client: Some(mock_client),
        }
    }

    #[cfg(not(test))]
    pub fn connect(&self) -> Result<RemoteStoreClient, String> {
        let auth = BasicAuthConfig::new(&self.settings.user, &self.settings.password);
        let config = ClientConfig::without_tls(auth);
        RemoteStoreClient::connect(&self.settings.endpoint, config)
            .map_err(|err| format!("connect: {err}"))
    }

    #[cfg(test)]
    pub fn connect(&self) -> Result<MockRemoteStoreClient, String> {
        self.mock_client
            .as_ref()
            .cloned()
            .ok_or_else(|| "connect: mock client not configured".to_string())
    }

    pub fn settings(&self) -> &RollblockClientSettings {
        &self.settings
    }
}

impl fmt::Debug for RollblockPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RollblockPool")
            .field("endpoint", &self.settings.endpoint)
            .field("user", &self.settings.user)
            .finish()
    }
}

pub fn build_rollblock_client_settings(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
) -> RollblockClientSettings {
    RollblockClientSettings {
        endpoint: format!("{host}:{port}"),
        user: user.to_string(),
        password: password.to_string(),
    }
}

pub fn build_rollblock_pool(host: &str, port: u16, user: &str, password: &str) -> RollblockPool {
    let settings = build_rollblock_client_settings(host, port, user, password);
    RollblockPool::new(settings)
}

/// Verifies the rollblock server is reachable by opening and closing a client connection.
pub async fn ensure_rollblock_available(pool: &RollblockPool) -> Result<(), String> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let client = pool.connect()?;
        client.close().map_err(|err| format!("close: {err}"))
    })
    .await
    .map_err(|err| format!("join: {err}"))?
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct MockRemoteStoreClient {
    closed: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<Vec<[u8; 8]>>>>,
    responses: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
}

#[cfg(test)]
impl MockRemoteStoreClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn was_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn calls(&self) -> Vec<Vec<[u8; 8]>> {
        self.calls.lock().unwrap().clone()
    }

    pub fn push_response(&self, values: Vec<Vec<u8>>) {
        self.responses.lock().unwrap().push(values);
    }

    pub fn get(&mut self, keys: &[[u8; 8]]) -> Result<Vec<Vec<u8>>, String> {
        self.calls.lock().unwrap().push(keys.to_vec());
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            Ok(vec![Vec::new(); keys.len()])
        } else {
            Ok(responses.remove(0))
        }
    }

    pub fn close(&self) -> Result<(), String> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[test]
    fn build_rollblock_client_settings_formats_endpoint() {
        let settings = build_rollblock_client_settings("example.org", 1234, "user", "pass");

        assert_eq!(settings.endpoint, "example.org:1234");
        assert_eq!(settings.user, "user");
        assert_eq!(settings.password, "pass");
    }

    #[test]
    fn connect_returns_error_for_unreachable_endpoint() {
        let pool = build_rollblock_pool("127.0.0.1", 0, "user", "pass");
        let result = pool.connect();

        assert!(
            result.is_err(),
            "expected connection failure, got {result:?}"
        );
    }

    #[test]
    fn mock_client_records_get_calls() {
        let mut mock = MockRemoteStoreClient::new();
        let keys = vec![[1u8; 8], [2u8; 8]];

        let values = mock.get(&keys).expect("mock get");

        assert_eq!(values.len(), keys.len());
        assert_eq!(mock.calls(), vec![keys]);
    }

    #[test]
    fn settings_returns_config() {
        let settings = build_rollblock_client_settings("host", 42, "user", "pass");
        let pool = RollblockPool::with_mock(settings.clone(), MockRemoteStoreClient::new());

        assert_eq!(pool.settings().endpoint, settings.endpoint);
        assert_eq!(pool.settings().user, settings.user);
        assert_eq!(pool.settings().password, settings.password);
    }

    #[tokio::test]
    async fn ensure_rollblock_available_closes_mock_connection() {
        let mock = MockRemoteStoreClient::new();
        let settings = build_rollblock_client_settings("mock", 1, "user", "pass");
        let pool = RollblockPool::with_mock(settings, mock.clone());

        ensure_rollblock_available(&pool)
            .await
            .expect("mock connection should succeed");

        assert!(mock.was_closed(), "mock connection should be closed");
    }

    #[tokio::test]
    async fn ensure_rollblock_available_propagates_connect_errors() {
        let pool = build_rollblock_pool("127.0.0.1", 0, "user", "pass");

        let result = timeout(Duration::from_secs(2), ensure_rollblock_available(&pool)).await;

        let err = result
            .expect("timeout waiting for ensure_rollblock_available")
            .expect_err("expected connect error");
        assert!(
            err.contains("connect") || err.contains("close"),
            "unexpected error message: {err}"
        );
    }
}
