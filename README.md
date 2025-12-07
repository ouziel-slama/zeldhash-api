# mhinapi

[![Tests](https://github.com/ouziel-slama/mhinapi/actions/workflows/tests.yml/badge.svg)](https://github.com/ouziel-slama/mhinapi/actions/workflows/tests.yml)
[![Coverage](https://codecov.io/github/ouziel-slama/mhinapi/graph/badge.svg?token=KHHE38EOC9)](https://codecov.io/github/ouziel-slama/mhinapi)
[![Format](https://github.com/ouziel-slama/mhinapi/actions/workflows/fmt.yml/badge.svg)](https://github.com/ouziel-slama/mhinapi/actions/workflows/fmt.yml)
[![Clippy](https://github.com/ouziel-slama/mhinapi/actions/workflows/clippy.yml/badge.svg)](https://github.com/ouziel-slama/mhinapi/actions/workflows/clippy.yml)
[![Crates.io](https://img.shields.io/crates/v/mhinapi.svg)](https://crates.io/crates/mhinapi)
[![Docs.rs](https://docs.rs/mhinapi/badge.svg)](https://docs.rs/mhinapi)

mhinapi is a REST API exposing [My Hash Is Nice](https://myhashisnice.org/) database over HTTP. It reads from the SQLite database produced by the mhinparser collector and uses a rollblock server to fetch UTXO balances while also querying an Electrum-compatible API for address data.

## Requirements

- Rust 1.81+ (Edition 2021)
- `mhinparser` collector running to populate both the SQLite stats database (expected filename: `mhinstats.sqlite3`) and the rollblock store
- Access to a rollblock server (host/port/user/password)
- Network access to an Electrum-compatible API (default: `https://mempool.space/api/`)

By default the SQLite file is looked up in the platform data directory for the `org/myhashisnice/mhinparser` application (e.g. `~/.local/share/mhinparser` on Linux). You can override the location with the CLI flag or environment variable below.

## Quickstart

```bash
cargo build --release
./target/release/mhinapi \
  --data-dir /path/to/data \
  --rollblock-host 127.0.0.1 \
  --rollblock-port 9443 \
  --electr-url https://mempool.space/api/ \
  --server-host 0.0.0.0 \
  --server-port 3000
```

### Configuration

All options can be set via CLI flags, environment variables, or a config file parsed by the `config` crate (`mhinapi.toml` is read automatically when present).

| Purpose            | CLI flag           | Env var                   | Default                         |
| ------------------ | ------------------ | ------------------------- | ------------------------------- |
| Data directory     | `--data-dir`       | `MHINAPI_DATA_DIR`        | platform user data dir          |
| Rollblock host     | `--rollblock-host` | `MHINAPI_ROLLBLOCK_HOST`  | `localhost`                     |
| Rollblock port     | `--rollblock-port` | `MHINAPI_ROLLBLOCK_PORT`  | `9443`                          |
| Rollblock user     | `--rollblock-user` | `MHINAPI_ROLLBLOCK_USER`  | `mhin`                          |
| Rollblock password | `--rollblock-password` | `MHINAPI_ROLLBLOCK_PASSWORD` | `mhin`                     |
| Electrum API URL   | `--electr-url`     | `MHINAPI_ELECTR_URL`      | `https://mempool.space/api/`    |
| HTTP bind host     | `--server-host`    | `MHINAPI_SERVER_HOST`     | `0.0.0.0`                       |
| HTTP bind port     | `--server-port`    | `MHINAPI_SERVER_PORT`     | `3000`                          |

## API overview

- `GET /` — Health check; verifies the SQLite pool is available.
- `GET /blocks` — Latest cumulative statistics from the `stats` table.
- `GET /blocks/:block_height` — Block-level stats plus rewards for the given height.
- `GET /rewards?offset=&limit=` — Paginated list of rewards sorted by reward and block height.
- `GET /addresses/:address/utxos` — Returns confirmed UTXOs for an address with rollblock balances.
- `GET /utxos/:txid:vout` — Balance for a single outpoint.
- `POST /utxos` — Batch balances for up to 100 outpoints.

Example:

```bash
curl http://localhost:3000/blocks/840000 | jq
curl "http://localhost:3000/rewards?limit=10&offset=0" | jq
curl -X POST http://localhost:3000/utxos \
  -H "Content-Type: application/json" \
  -d '{"utxos":["<txid>:0","<txid2>:1"]}'
```

The API returns `500` responses for rollblock/SQLite failures and `400` for malformed inputs; missing resources return `404`.

## Development

- Run tests: `cargo test`
- Format: `cargo fmt`

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.

