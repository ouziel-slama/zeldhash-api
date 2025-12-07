# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-12-07
### Added
- Initial Axum HTTP API exposing mhinparser-generated statistics from SQLite.
- Rollblock integration for computing UTXO balances.
- Endpoints for blocks, rewards, address UTXOs, and batch/single outpoint balances.
- CLI, config file, and environment variable overrides for all runtime settings.
- Test coverage for configuration loading, routing, and rollblock/SQLite helpers.

