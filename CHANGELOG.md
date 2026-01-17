# Changelog

All notable changes to this project will be documented in this file.

## [0.3.4] - 2026-01-17
### Added
- New `unconfirmed` query parameter for `/addresses/{address}/rewards` endpoint. When `true`, includes unconfirmed transactions from mempool.space where the txid starts with at least 6 zeros and the address is in the first non-OP_RETURN output.
- Unconfirmed rewards appear first in results with `reward: "unknown"` and `block_index: null`.
- New 502 error response for mempool.space API failures.

## [0.3.3] - 2026-01-17
### Changed
- UTXO balance decoding now treats negative values as zero to handle spent UTXO tombstones introduced in `zeldhash-protocol` v0.6.0.

## [0.3.2] - 2026-01-16
### Added
- New `GET /addresses/{address}/rewards` endpoint to fetch paginated rewards for a specific address, with optional `sort=zero_count` parameter.
- Added `address` field to all reward responses (`/blocks/{height}`, `/rewards`, `/rewards/{txid}`).

### Changed
- Upgraded `zeldhash-protocol` dependency from 0.5.0 to 0.6.0.

## [0.3.1] - 2026-01-11
### Fixed
- Rewards from the same block are now returned in insertion order (most recent first) by adding `rowid DESC` to all reward queries.

## [0.3.0] - 2026-01-10
### Changed
- Upgraded `zeldhash-protocol` dependency from 0.3.1 to 0.5.0.

## [0.2.2] - 2025-12-30
### Added
- New `GET /rewards/{txid}` endpoint to fetch rewards for a specific transaction.
- New `sort` query parameter for `/rewards` endpoint with `zero_count` option to order results by leading zeros first.

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

