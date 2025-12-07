//! Default configuration values and platform-specific paths.

use directories::ProjectDirs;
use std::path::PathBuf;

pub const DEFAULT_ELECTR_URL: &str = "https://mempool.space/api/";
pub const DEFAULT_ROLLBLOCK_HOST: &str = "localhost";
pub const DEFAULT_ROLLBLOCK_PASSWORD: &str = "mhin";
pub const DEFAULT_ROLLBLOCK_PORT: u16 = 9443;
pub const DEFAULT_ROLLBLOCK_USER: &str = "mhin";
pub const DEFAULT_SERVER_HOST: &str = "0.0.0.0";
pub const DEFAULT_SERVER_PORT: u16 = 3000;

const PROJECT_QUALIFIER: &str = "org";
const PROJECT_ORGANIZATION: &str = "myhashisnice";
// We intentionally keep using the mhinparser application id because this API
// only reads SQLite data produced by the mhinparser collector and should look
// in the same per-user data directory.
const PROJECT_APPLICATION: &str = "mhinparser";

/// Returns the platform-specific user data directory used by mhinparser/mhinapi.
pub fn default_data_dir_path() -> Option<PathBuf> {
    ProjectDirs::from(PROJECT_QUALIFIER, PROJECT_ORGANIZATION, PROJECT_APPLICATION)
        .map(|dirs| dirs.data_dir().to_path_buf())
}
