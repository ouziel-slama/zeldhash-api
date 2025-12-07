//! SQLite connection pool for reading mhinparser statistics.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;

pub type SqlitePool = Pool<SqliteConnectionManager>;

pub fn build_sqlite_pool(db_path: &Path) -> Result<SqlitePool, String> {
    if !db_path.is_file() {
        return Err(format!(
            "SQLite database not found at {}",
            db_path.display()
        ));
    }

    let manager = SqliteConnectionManager::file(db_path);
    Pool::builder()
        .build(manager)
        .map_err(|err| format!("build pool: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn build_sqlite_pool_fails_when_file_missing() {
        let tmp = tempdir().expect("temp dir");
        let missing_path = tmp.path().join("no_db.sqlite");

        match build_sqlite_pool(&missing_path) {
            Err(err) => assert!(
                err.contains("SQLite database not found"),
                "unexpected error message: {err}"
            ),
            Ok(_) => panic!("expected missing file error"),
        }
    }

    #[test]
    fn build_sqlite_pool_succeeds_for_existing_file() {
        let tmp = tempdir().expect("temp dir");
        let db_path = tmp.path().join("db.sqlite");

        // Create an empty SQLite database file the pool can open.
        Connection::open(&db_path).expect("create sqlite db");

        let pool = build_sqlite_pool(&db_path).expect("pool should build");
        let conn = pool.get().expect("connection from pool");

        let count: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .expect("query sqlite_master");
        assert!(count >= 0);
    }
}
