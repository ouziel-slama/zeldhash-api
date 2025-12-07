//! Configuration loading and merging for mhinapi.
//!
//! Settings are resolved in priority order: CLI flags override environment
//! variables, which override config file values, which override defaults.

use config::{ConfigError, Environment, File};
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
};

use crate::{
    cli::Cli,
    defaults::{
        default_data_dir_path, DEFAULT_ELECTR_URL, DEFAULT_ROLLBLOCK_HOST,
        DEFAULT_ROLLBLOCK_PASSWORD, DEFAULT_ROLLBLOCK_PORT, DEFAULT_ROLLBLOCK_USER,
        DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT,
    },
};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub data_dir: Option<PathBuf>,
    #[serde(default = "default_rollblock_host")]
    pub rollblock_host: String,
    #[serde(default = "default_rollblock_port")]
    pub rollblock_port: u16,
    #[serde(default = "default_rollblock_user")]
    pub rollblock_user: String,
    #[serde(default = "default_rollblock_password")]
    pub rollblock_password: String,
    #[serde(default = "default_electr_url")]
    pub electr_url: String,
    #[serde(default = "default_server_host")]
    pub server_host: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
}

fn default_rollblock_host() -> String {
    DEFAULT_ROLLBLOCK_HOST.to_string()
}

fn default_rollblock_port() -> u16 {
    DEFAULT_ROLLBLOCK_PORT
}

fn default_electr_url() -> String {
    DEFAULT_ELECTR_URL.to_string()
}

fn default_rollblock_user() -> String {
    DEFAULT_ROLLBLOCK_USER.to_string()
}

fn default_rollblock_password() -> String {
    DEFAULT_ROLLBLOCK_PASSWORD.to_string()
}

fn default_server_host() -> String {
    DEFAULT_SERVER_HOST.to_string()
}

fn default_server_port() -> u16 {
    DEFAULT_SERVER_PORT
}

impl AppConfig {
    pub fn load(cli: &Cli) -> Result<Self, ConfigError> {
        let mut builder = config::Config::builder()
            .set_default("electr_url", default_electr_url())?
            .set_default("rollblock_host", default_rollblock_host())?
            .set_default("rollblock_port", default_rollblock_port())?
            .set_default("rollblock_user", default_rollblock_user())?
            .set_default("rollblock_password", default_rollblock_password())?
            .set_default("server_host", default_server_host())?
            .set_default("server_port", default_server_port())?;

        if let Some(default_path) = default_data_dir_path() {
            builder =
                builder.set_default("data_dir", default_path.to_string_lossy().to_string())?;
        }

        if let Some(path) = cli.config_file.as_deref() {
            builder = builder.add_source(File::from(path));
        } else {
            let default_path = Path::new("mhinapi.toml");
            if default_path.exists() {
                builder = builder.add_source(File::from(default_path));
            }
        }

        builder = builder.add_source(
            Environment::with_prefix("MHINAPI")
                .separator("__")
                .list_separator(","),
        );

        for (env_key, config_key) in [
            ("MHINAPI_DATA_DIR", "data_dir"),
            ("MHINAPI_ROLLBLOCK_HOST", "rollblock_host"),
            ("MHINAPI_ROLLBLOCK_PORT", "rollblock_port"),
            ("MHINAPI_ROLLBLOCK_USER", "rollblock_user"),
            ("MHINAPI_ROLLBLOCK_PASSWORD", "rollblock_password"),
            ("MHINAPI_ELECTR_URL", "electr_url"),
            ("MHINAPI_SERVER_HOST", "server_host"),
            ("MHINAPI_SERVER_PORT", "server_port"),
        ] {
            if let Ok(value) = env::var(env_key) {
                builder = builder.set_override(config_key, value)?;
            }
        }

        if let Some(value) = cli.data_dir.as_ref() {
            builder = builder.set_override("data_dir", value.to_string_lossy().to_string())?;
        }
        if let Some(value) = cli.rollblock_host.as_ref() {
            builder = builder.set_override("rollblock_host", value.clone())?;
        }
        if let Some(value) = cli.rollblock_port.as_ref() {
            builder = builder.set_override("rollblock_port", value.to_string())?;
        }
        if let Some(value) = cli.rollblock_user.as_ref() {
            builder = builder.set_override("rollblock_user", value.clone())?;
        }
        if let Some(value) = cli.rollblock_password.as_ref() {
            builder = builder.set_override("rollblock_password", value.clone())?;
        }
        if let Some(value) = cli.electr_url.as_ref() {
            builder = builder.set_override("electr_url", value.clone())?;
        }
        if let Some(value) = cli.server_host.as_ref() {
            builder = builder.set_override("server_host", value.clone())?;
        }
        if let Some(value) = cli.server_port.as_ref() {
            builder = builder.set_override("server_port", value.to_string())?;
        }

        let merged = builder.build()?;

        merged.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::Cli,
        defaults::{
            DEFAULT_ELECTR_URL, DEFAULT_ROLLBLOCK_HOST, DEFAULT_ROLLBLOCK_PASSWORD,
            DEFAULT_ROLLBLOCK_PORT, DEFAULT_ROLLBLOCK_USER, DEFAULT_SERVER_HOST,
            DEFAULT_SERVER_PORT,
        },
    };
    use std::{
        env,
        fs::File,
        io::Write,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    use tempfile::tempdir;

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock poisoned")
    }

    fn set_env(key: &str, value: &str) {
        unsafe { env::set_var(key, value) };
    }

    fn remove_env(key: &str) {
        unsafe { env::remove_var(key) };
    }

    fn clear_mhinapi_env() {
        for key in [
            "MHINAPI_DATA_DIR",
            "MHINAPI_ROLLBLOCK_HOST",
            "MHINAPI_ROLLBLOCK_PORT",
            "MHINAPI_ROLLBLOCK_USER",
            "MHINAPI_ROLLBLOCK_PASSWORD",
            "MHINAPI_ELECTR_URL",
            "MHINAPI_SERVER_HOST",
            "MHINAPI_SERVER_PORT",
        ] {
            remove_env(key);
        }
    }

    struct DirGuard {
        original: PathBuf,
    }

    impl DirGuard {
        fn change_to(path: &Path) -> Self {
            let original = env::current_dir().expect("failed to read current dir");
            env::set_current_dir(path).expect("failed to change directory");
            Self { original }
        }
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            env::set_current_dir(&self.original).expect("failed to restore working dir");
        }
    }

    fn assert_default_data_dir(actual: &Option<PathBuf>) {
        match default_data_dir_path() {
            Some(expected) => assert_eq!(actual.as_deref(), Some(expected.as_path())),
            None => assert!(actual.is_none()),
        }
    }

    fn cli_with_all_overrides() -> Cli {
        Cli {
            config_file: None,
            data_dir: Some(PathBuf::from("/tmp/mhinapi_cli")),
            rollblock_host: Some("cli-host".into()),
            rollblock_port: Some(4242),
            rollblock_user: Some("cli-user".into()),
            rollblock_password: Some("cli-pass".into()),
            electr_url: Some("https://cli.example/".into()),
            server_host: Some("127.0.0.1".into()),
            server_port: Some(9999),
        }
    }

    #[test]
    fn load_prefers_cli_over_env_and_defaults() {
        let _guard = test_lock();
        clear_mhinapi_env();
        set_env("MHINAPI_ELECTR_URL", "https://env.example/");

        let cfg = AppConfig::load(&cli_with_all_overrides()).expect("config should load");

        assert_eq!(cfg.data_dir.as_deref(), Some(Path::new("/tmp/mhinapi_cli")));
        assert_eq!(cfg.rollblock_host, "cli-host");
        assert_eq!(cfg.rollblock_port, 4242);
        assert_eq!(cfg.rollblock_user, "cli-user");
        assert_eq!(cfg.rollblock_password, "cli-pass");
        assert_eq!(cfg.electr_url, "https://cli.example/");
        assert_eq!(cfg.server_host, "127.0.0.1");
        assert_eq!(cfg.server_port, 9999);

        clear_mhinapi_env();
    }

    #[test]
    fn load_combines_config_file_and_env_when_cli_missing() {
        let _guard = test_lock();
        clear_mhinapi_env();

        let temp_dir = tempdir().expect("tempdir");
        let config_path = temp_dir.path().join("config.toml");
        let mut file = File::create(&config_path).expect("config file");
        writeln!(
            file,
            r#"
rollblock_host = "file-host"
rollblock_port = 2223
rollblock_user = "file-user"
server_host = "file-server"
server_port = 3030
"#
        )
        .expect("write config");

        set_env("MHINAPI_ROLLBLOCK_PASSWORD", "env-pass");

        let cli = Cli {
            config_file: Some(config_path.clone()),
            data_dir: None,
            rollblock_host: None,
            rollblock_port: None,
            rollblock_user: None,
            rollblock_password: None,
            electr_url: None,
            server_host: None,
            server_port: None,
        };

        let cfg = AppConfig::load(&cli).expect("config should load");

        assert_default_data_dir(&cfg.data_dir);
        assert_eq!(cfg.rollblock_host, "file-host");
        assert_eq!(cfg.rollblock_port, 2223);
        assert_eq!(cfg.rollblock_user, "file-user");
        assert_eq!(cfg.rollblock_password, "env-pass");
        assert_eq!(cfg.server_host, "file-server");
        assert_eq!(cfg.server_port, 3030);
        assert_eq!(cfg.electr_url, DEFAULT_ELECTR_URL);

        clear_mhinapi_env();
    }

    #[test]
    fn load_reads_default_config_file_when_present() {
        let _guard = test_lock();
        clear_mhinapi_env();

        let temp_dir = tempdir().expect("tempdir");
        let default_config_path = temp_dir.path().join("mhinapi.toml");
        let mut file = File::create(&default_config_path).expect("default config file");
        writeln!(file, r#"electr_url = "https://default.example/api""#)
            .expect("write default config");

        let _dir_guard = DirGuard::change_to(temp_dir.path());

        let cli = Cli {
            config_file: None,
            data_dir: None,
            rollblock_host: None,
            rollblock_port: None,
            rollblock_user: None,
            rollblock_password: None,
            electr_url: None,
            server_host: None,
            server_port: None,
        };

        let cfg = AppConfig::load(&cli).expect("config should load");

        assert_default_data_dir(&cfg.data_dir);
        assert_eq!(cfg.rollblock_host, DEFAULT_ROLLBLOCK_HOST);
        assert_eq!(cfg.rollblock_port, DEFAULT_ROLLBLOCK_PORT);
        assert_eq!(cfg.rollblock_user, DEFAULT_ROLLBLOCK_USER);
        assert_eq!(cfg.rollblock_password, DEFAULT_ROLLBLOCK_PASSWORD);
        assert_eq!(cfg.server_host, DEFAULT_SERVER_HOST);
        assert_eq!(cfg.server_port, DEFAULT_SERVER_PORT);
        assert_eq!(cfg.electr_url, "https://default.example/api");

        clear_mhinapi_env();
    }
}
