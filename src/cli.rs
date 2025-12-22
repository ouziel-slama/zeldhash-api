//! Command-line interface for zeldhash-api.
//!
//! This module defines the CLI arguments parsed by [`clap`] and used to
//! configure the server at startup.

use clap::{CommandFactory, FromArgMatches, Parser};
use std::{env, ffi::OsString, path::PathBuf};

use crate::defaults::{
    default_data_dir_path, DEFAULT_ELECTR_URL, DEFAULT_ROLLBLOCK_HOST, DEFAULT_ROLLBLOCK_PASSWORD,
    DEFAULT_ROLLBLOCK_PORT, DEFAULT_ROLLBLOCK_USER, DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT,
};

/// Command-line flags used to bootstrap configuration.
#[derive(Debug, Parser)]
#[command(name = "zeldhash-api", about = "REST API serving ZeldHash databases")]
pub struct Cli {
    /// Optional path to a configuration file (TOML, YAML, or JSON supported by `config` crate, defaults to `zeldhash-api.toml` when present)
    #[arg(long, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Directory containing the stats SQLite database
    #[arg(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Host for the rollblock database
    #[arg(long, value_name = "HOST")]
    pub rollblock_host: Option<String>,

    /// Port for the rollblock database
    #[arg(long, value_name = "PORT")]
    pub rollblock_port: Option<u16>,

    /// User for the rollblock database (default: zeld)
    #[arg(long, value_name = "USER")]
    pub rollblock_user: Option<String>,

    /// Password for the rollblock database (default: zeld)
    #[arg(long, value_name = "PASSWORD")]
    pub rollblock_password: Option<String>,

    /// Base URL for the Electrum-compatible API (default: <https://mempool.space/api/>)
    #[arg(long, value_name = "URL")]
    pub electr_url: Option<String>,

    /// Whether to enable CORS responses (default: enabled)
    #[arg(long, value_name = "BOOL")]
    pub cors_enabled: Option<bool>,

    /// Bind address for the HTTP server (default: 0.0.0.0)
    #[arg(long, value_name = "HOST")]
    pub server_host: Option<String>,

    /// Bind port for the HTTP server (default: 3000)
    #[arg(long, value_name = "PORT")]
    pub server_port: Option<u16>,
}

impl Cli {
    pub fn gather() -> Self {
        Self::gather_from(Self::runtime_args())
    }

    pub fn gather_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut cmd = <Self as CommandFactory>::command();

        if let Some(default_path) = default_data_dir_path() {
            let help = format!(
                "Directory containing the stats SQLite database (default: {})",
                default_path.display()
            );
            // The argument id uses the field name (data_dir), not the long flag (data-dir).
            cmd = cmd.mut_arg("data_dir", |arg| arg.help(help));
        }

        cmd = cmd.mut_arg("rollblock_host", |arg| {
            arg.help(format!(
                "Host for the rollblock database (default: {DEFAULT_ROLLBLOCK_HOST})"
            ))
        });

        cmd = cmd.mut_arg("rollblock_port", |arg| {
            arg.help(format!(
                "Port for the rollblock database (default: {DEFAULT_ROLLBLOCK_PORT})"
            ))
        });

        cmd = cmd.mut_arg("rollblock_user", |arg| {
            arg.help(format!(
                "User for the rollblock database (default: {DEFAULT_ROLLBLOCK_USER})"
            ))
        });

        cmd = cmd.mut_arg("rollblock_password", |arg| {
            arg.help(format!(
                "Password for the rollblock database (default: {DEFAULT_ROLLBLOCK_PASSWORD})"
            ))
        });

        cmd = cmd.mut_arg("electr_url", |arg| {
            arg.help(format!(
                "Base URL for the Electrum-compatible API (default: {DEFAULT_ELECTR_URL})"
            ))
        });

        cmd = cmd.mut_arg("cors_enabled", |arg| {
            arg.help("Whether to enable CORS responses (default: true)")
        });

        cmd = cmd.mut_arg("server_host", |arg| {
            arg.help(format!(
                "Bind address for the HTTP server (default: {DEFAULT_SERVER_HOST})"
            ))
        });

        cmd = cmd.mut_arg("server_port", |arg| {
            arg.help(format!(
                "Bind port for the HTTP server (default: {DEFAULT_SERVER_PORT})"
            ))
        });

        let matches = cmd.get_matches_from(args);
        match <Self as FromArgMatches>::from_arg_matches(&matches) {
            Ok(cli) => cli,
            Err(err) => err.exit(),
        }
    }

    fn runtime_args() -> Vec<OsString> {
        #[cfg(test)]
        if let Ok(raw) = env::var("ZELDHASH_API_TEST_ARGS") {
            return raw.split_whitespace().map(OsString::from).collect();
        }

        env::args_os().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn set_env(key: &str, value: &str) {
        unsafe { env::set_var(key, value) };
    }

    fn remove_env(key: &str) {
        unsafe { env::remove_var(key) };
    }

    fn clear_test_args() {
        remove_env("ZELDHASH_API_TEST_ARGS");
    }

    #[test]
    fn gather_parses_all_flags_from_env_overrides() {
        let tmp_dir = tempdir().unwrap();
        let args = format!(
            "zeldhash-api --data-dir {} --rollblock-host example.com --rollblock-port 1234 --rollblock-user alice --rollblock-password secret --electr-url https://example.com/api --cors-enabled false --server-host 127.0.0.1 --server-port 4040",
            tmp_dir.path().display()
        );
        set_env("ZELDHASH_API_TEST_ARGS", &args);

        let cli = Cli::gather();

        assert_eq!(cli.data_dir.as_deref(), Some(tmp_dir.path()));
        assert_eq!(cli.rollblock_host.as_deref(), Some("example.com"));
        assert_eq!(cli.rollblock_port, Some(1234));
        assert_eq!(cli.rollblock_user.as_deref(), Some("alice"));
        assert_eq!(cli.rollblock_password.as_deref(), Some("secret"));
        assert_eq!(cli.electr_url.as_deref(), Some("https://example.com/api"));
        assert_eq!(cli.cors_enabled, Some(false));
        assert_eq!(cli.server_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(cli.server_port, Some(4040));

        clear_test_args();
    }

    #[test]
    fn gather_from_accepts_minimal_arguments() {
        let cli = Cli::gather_from(["zeldhash-api"]);

        assert!(cli.data_dir.is_none());
        assert!(cli.rollblock_host.is_none());
        assert!(cli.rollblock_port.is_none());
        assert!(cli.rollblock_user.is_none());
        assert!(cli.rollblock_password.is_none());
        assert!(cli.electr_url.is_none());
        assert!(cli.cors_enabled.is_none());
        assert!(cli.server_host.is_none());
        assert!(cli.server_port.is_none());
    }
}
