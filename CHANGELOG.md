# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2025-12-22
### Added
- CORS support with permissive policy via `tower-http`.
- New `cors_enabled` configuration option (CLI flag, config file, and `ZELDHASH_API_CORS_ENABLED` env var).
- CORS is enabled by default.

## [0.2.0] - 2025-12-13
### Changed
- Upgraded rollblock to 0.4.1 with typed `StoreKey` and `key-12` support.
- Switched UTXO key hashing to `zeldhash-protocol` helpers, removing the xxhash dependency.
- Project renamed to zeldhash-api (binary, docs, badges, and crate metadata).
- Env/config prefixes now use `ZELDHASH_API_*` and default config file is `zeldhash-api.toml`.
- Default data directory now points to `org/zeldhash/zeldhash-parser` and expects `zeldstats.sqlite3`.
- Default rollblock credentials switched to user/password `zeld` to align with the new parser naming.

## [0.1.0] - 2025-12-07
### Added
- Initial Axum HTTP API exposing zeldhash-parser-generated statistics from SQLite.
- Rollblock integration for computing UTXO balances.
- Endpoints for blocks, rewards, address UTXOs, and batch/single outpoint balances.
- CLI, config file, and environment variable overrides for all runtime settings.
- Test coverage for configuration loading, routing, and rollblock/SQLite helpers.

