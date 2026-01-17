//! HTTP route handlers for the zeldhash-api REST API.
//!
//! Provides endpoints for querying block statistics, rewards, and UTXO balances.

use std::str::FromStr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bitcoin::Txid;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::task::spawn_blocking;
use tower_http::cors::CorsLayer;
use zeldhash_protocol::helpers::compute_utxo_key;

use crate::{
    rollblockpool::{ensure_rollblock_available, RollblockPool, StoreKey},
    AppState,
};

type ApiResult<T> = Result<T, (StatusCode, Json<Value>)>;

const ERR_SQLITE_OR_ROLLBLOCK_UNAVAILABLE: &str = "SQLite or rollblock pool unavailable.";
const ERR_STATS_EMPTY: &str = "No rows available in the stats table yet.";
const ERR_INVALID_JSON_OR_SQLITE_FAILURE: &str = "Invalid JSON in the database or SQLite failure.";
const ERR_BLOCK_NOT_FOUND: &str = "Block not found in the stats table.";
const ERR_BLOCK_HEIGHT_RANGE: &str = "`block_height` exceeds 64-bit signed range.";
const ERR_OFFSET_RANGE: &str = "`offset` exceeds 64-bit signed range.";
const ERR_SQLITE_FAILURE: &str = "SQLite failure.";
const ERR_TOO_MANY_UTXOS_FOR_ADDRESS: &str = "More than 500 confirmed UTXOs for the address.";
const ERR_REWARD_NOT_FOUND: &str = "Reward not found for txid.";
const ERR_REWARD_NOT_FOUND_FOR_ADDRESS: &str = "No rewards found for address.";
const ERR_MALFORMED_TXID: &str = "Malformed txid.";
const ERR_UNSUPPORTED_REWARD_SORT: &str =
    "Unsupported sort. Use 'zero_count' or omit the parameter.";
const ERR_ELECTRUM_FAILURE: &str = "Downstream Electrum API failure or invalid response.";
const ERR_MEMPOOL_FAILURE: &str = "Downstream mempool API failure or invalid response.";
const ERR_ROLLBLOCK_FAILURE: &str = "Rollblock failure.";
const ERR_MALFORMED_OUTPOINT: &str = "Malformed txid or vout.";
const ERR_TOO_MANY_OUTPOINTS: &str = "More than 100 outpoints or malformed entries.";

fn json_error(status: StatusCode, message: &'static str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

const DEFAULT_REWARDS_LIMIT: usize = 50;
const MAX_REWARDS_LIMIT: usize = 500;
const MAX_ADDRESS_UTXOS: usize = 500;
const ROLLBLOCK_BATCH_SIZE: usize = 100;

pub fn create_router(state: AppState, enable_cors: bool) -> Router {
    let router = Router::new()
        .route("/", get(root))
        .route("/rewards", get(rewards))
        .route("/rewards/{txid}", get(rewards_by_txid))
        .route("/blocks", get(blocks))
        .route("/blocks/{block_height}", get(block_details))
        .route("/addresses/{address}/utxos", get(address_utxos))
        .route("/addresses/{address}/rewards", get(rewards_by_address))
        .route(
            "/addresses/{address}/rewards/count",
            get(rewards_count_by_address),
        )
        .route("/utxos", post(utxo_balances))
        .route("/utxos/{outpoint}", get(utxo_balance))
        .with_state(state);

    if enable_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

pub async fn root(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let pool = state.sqlite_pool.clone();
    spawn_blocking(move || {
        pool.get()
            .map(|_| ())
            .map_err(|err| format!("get sqlite connection: {err}"))
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_SQLITE_OR_ROLLBLOCK_UNAVAILABLE,
        )
    })?
    .map_err(|err| {
        eprintln!("{err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_SQLITE_OR_ROLLBLOCK_UNAVAILABLE,
        )
    })?;

    ensure_rollblock_available(&state.rollblock)
        .await
        .map_err(|err| {
            eprintln!("rollblock unavailable: {err}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_SQLITE_OR_ROLLBLOCK_UNAVAILABLE,
            )
        })?;

    Ok(Json(json!({ "status": "ok" })))
}

pub async fn blocks(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let pool = state.sqlite_pool.clone();
    let cumul_stats = spawn_blocking(move || {
        let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;
        let mut stmt = conn
            .prepare("SELECT cumul_stats FROM stats ORDER BY block_index DESC LIMIT 1")
            .map_err(|err| format!("prepare statement: {err}"))?;

        match stmt.query_row([], |row| row.get::<_, String>(0)) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(format!("query row: {err}")),
        }
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?
    .map_err(|err| {
        eprintln!("failed to fetch cumul_stats: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?;

    let Some(cumul_stats) = cumul_stats else {
        return Err(json_error(StatusCode::NOT_FOUND, ERR_STATS_EMPTY));
    };

    let cumul_stats: Value = serde_json::from_str(&cumul_stats).map_err(|err| {
        eprintln!("failed to parse cumul_stats JSON: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?;

    Ok(Json(cumul_stats))
}

pub async fn block_details(
    Path(block_height): Path<u64>,
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let block_index = i64::try_from(block_height).map_err(|_| {
        eprintln!("block height {block_height} exceeds i64 range");
        json_error(StatusCode::BAD_REQUEST, ERR_BLOCK_HEIGHT_RANGE)
    })?;

    let pool = state.sqlite_pool.clone();
    let result = spawn_blocking(move || {
        let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;

        let mut stats_stmt = conn
            .prepare("SELECT block_stats, cumul_stats FROM stats WHERE block_index = ?1")
            .map_err(|err| format!("prepare stats statement: {err}"))?;

        let stats_row = match stats_stmt.query_row([block_index], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            Ok(row) => Some(row),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(err) => return Err(format!("query stats row: {err}")),
        };

        let Some((block_stats, cumul_stats)) = stats_row else {
            return Ok(None);
        };

        let mut rewards_stmt = conn
            .prepare(
                "SELECT txid, vout, zero_count, reward, address \
                 FROM rewards \
                 WHERE block_index = ?1 \
                 ORDER BY rowid DESC, reward DESC, zero_count DESC, txid ASC, vout ASC",
            )
            .map_err(|err| format!("prepare rewards statement: {err}"))?;

        let rewards = rewards_stmt
            .query_map([block_index], |row| {
                Ok(json!({
                    "txid": row.get::<_, String>(0)?,
                    "vout": row.get::<_, i64>(1)?,
                    "zero_count": row.get::<_, i64>(2)?,
                    "reward": row.get::<_, i64>(3)?,
                    "address": row.get::<_, Option<String>>(4)?,
                }))
            })
            .map_err(|err| format!("query rewards map: {err}"))?
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|err| format!("collect rewards: {err}"))?;

        Ok(Some((block_stats, cumul_stats, rewards)))
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?
    .map_err(|err| {
        eprintln!("sqlite error: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?;

    let Some((block_stats, cumul_stats, rewards)) = result else {
        return Err(json_error(StatusCode::NOT_FOUND, ERR_BLOCK_NOT_FOUND));
    };

    let block_stats: Value = serde_json::from_str(&block_stats).map_err(|err| {
        eprintln!("failed to parse block_stats JSON: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?;

    let cumul_stats: Value = serde_json::from_str(&cumul_stats).map_err(|err| {
        eprintln!("failed to parse cumul_stats JSON: {err}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INVALID_JSON_OR_SQLITE_FAILURE,
        )
    })?;

    Ok(Json(json!({
        "block_index": block_height,
        "block_stats": block_stats,
        "cumul_stats": cumul_stats,
        "rewards": rewards,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RewardsQuery {
    offset: Option<usize>,
    limit: Option<usize>,
    sort: Option<String>,
    #[serde(default)]
    unconfirmed: bool,
}

#[derive(Debug, Deserialize)]
struct AddressUtxo {
    txid: String,
    vout: u32,
    status: AddressUtxoStatus,
}

#[derive(Debug, Deserialize)]
struct AddressUtxoStatus {
    confirmed: bool,
}

/// Transaction output from mempool.space API.
#[derive(Debug, Deserialize)]
struct MempoolTxVout {
    scriptpubkey_type: Option<String>,
    scriptpubkey_address: Option<String>,
}

/// Transaction from mempool.space API.
#[derive(Debug, Deserialize)]
struct MempoolTx {
    txid: String,
    vout: Vec<MempoolTxVout>,
}

const MIN_ZERO_COUNT: usize = 6;

pub async fn rewards(
    State(state): State<AppState>,
    Query(params): Query<RewardsQuery>,
) -> ApiResult<impl IntoResponse> {
    let pool = state.sqlite_pool.clone();
    let offset_usize = params.offset.unwrap_or(0);
    let offset = i64::try_from(offset_usize).map_err(|_| {
        eprintln!("offset {offset_usize} exceeds i64 range");
        json_error(StatusCode::BAD_REQUEST, ERR_OFFSET_RANGE)
    })?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_REWARDS_LIMIT)
        .min(MAX_REWARDS_LIMIT) as i64;

    let order_clause = match params.sort.as_deref() {
        None | Some("") => {
            "block_index DESC, rowid DESC, reward DESC, zero_count DESC, txid ASC, vout ASC"
                .to_string()
        }
        Some("zero_count") => {
            "zero_count DESC, reward DESC, block_index DESC, rowid DESC, txid ASC, vout ASC"
                .to_string()
        }
        Some(other) => {
            eprintln!("unsupported rewards sort: {other}");
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_UNSUPPORTED_REWARD_SORT,
            ));
        }
    };

    let rewards = spawn_blocking(move || {
        let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT block_index, txid, vout, zero_count, reward, address \
                 FROM rewards \
                 ORDER BY {order_clause} \
                 LIMIT ?1 OFFSET ?2"
            ))
            .map_err(|err| format!("prepare rewards statement: {err}"))?;

        let mapped = stmt
            .query_map([limit, offset], |row| {
                Ok(json!({
                    "block_index": row.get::<_, i64>(0)?,
                    "txid": row.get::<_, String>(1)?,
                    "vout": row.get::<_, i64>(2)?,
                    "zero_count": row.get::<_, i64>(3)?,
                    "reward": row.get::<_, i64>(4)?,
                    "address": row.get::<_, Option<String>>(5)?,
                }))
            })
            .map_err(|err| format!("query rewards map: {err}"))?;

        let rows = mapped
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|err| format!("collect rewards: {err}"))?;

        Ok::<_, String>(rows)
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?
    .map_err(|err| {
        eprintln!("failed to fetch rewards: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?;

    Ok(Json(rewards))
}

pub async fn rewards_by_txid(
    Path(txid_str): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let txid = Txid::from_str(&txid_str).map_err(|err| {
        eprintln!("invalid txid {txid_str}: {err}");
        json_error(StatusCode::BAD_REQUEST, ERR_MALFORMED_TXID)
    })?;
    let txid = txid.to_string();

    let pool = state.sqlite_pool.clone();
    let rewards = spawn_blocking(move || {
        let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT block_index, txid, vout, zero_count, reward, address \
                 FROM rewards \
                 WHERE txid = ?1 \
                 ORDER BY block_index DESC, rowid DESC, reward DESC, zero_count DESC, vout ASC",
            )
            .map_err(|err| format!("prepare rewards-by-txid statement: {err}"))?;

        let mapped = stmt
            .query_map([txid], |row| {
                Ok(json!({
                    "block_index": row.get::<_, i64>(0)?,
                    "txid": row.get::<_, String>(1)?,
                    "vout": row.get::<_, i64>(2)?,
                    "zero_count": row.get::<_, i64>(3)?,
                    "reward": row.get::<_, i64>(4)?,
                    "address": row.get::<_, Option<String>>(5)?,
                }))
            })
            .map_err(|err| format!("query rewards-by-txid map: {err}"))?;

        let rows = mapped
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|err| format!("collect rewards-by-txid: {err}"))?;

        Ok::<_, String>(rows)
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?
    .map_err(|err| {
        eprintln!("failed to fetch rewards by txid: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?;

    if rewards.is_empty() {
        return Err(json_error(StatusCode::NOT_FOUND, ERR_REWARD_NOT_FOUND));
    }

    Ok(Json(rewards))
}

/// Counts leading zeros in a hex txid string.
fn count_leading_zeros(txid: &str) -> usize {
    txid.chars().take_while(|c| *c == '0').count()
}

/// Fetches unconfirmed transactions from mempool.space and returns rewards
/// for transactions where:
/// - The txid starts with at least MIN_ZERO_COUNT zeros
/// - The provided address is in the first non-OP_RETURN output
async fn fetch_unconfirmed_rewards(
    http_client: &reqwest::Client,
    base_url: &str,
    address: &str,
) -> ApiResult<Vec<Value>> {
    let url = format!("{base_url}/address/{address}/txs/mempool");
    let txs: Vec<MempoolTx> = http_client
        .get(&url)
        .send()
        .await
        .map_err(|err| {
            eprintln!("failed to fetch mempool txs for {address}: {err}");
            json_error(StatusCode::BAD_GATEWAY, ERR_MEMPOOL_FAILURE)
        })?
        .json()
        .await
        .map_err(|err| {
            eprintln!("failed to decode mempool response for {address}: {err}");
            json_error(StatusCode::BAD_GATEWAY, ERR_MEMPOOL_FAILURE)
        })?;

    let mut unconfirmed_rewards = Vec::new();

    for tx in txs {
        // Check if txid starts with at least MIN_ZERO_COUNT zeros
        let zero_count = count_leading_zeros(&tx.txid);
        if zero_count < MIN_ZERO_COUNT {
            continue;
        }

        // Find the first non-OP_RETURN output
        let first_non_op_return = tx
            .vout
            .iter()
            .enumerate()
            .find(|(_, vout)| vout.scriptpubkey_type.as_deref() != Some("op_return"));

        // Check if the address is in the first non-OP_RETURN output
        if let Some((vout_index, vout)) = first_non_op_return {
            if vout.scriptpubkey_address.as_deref() == Some(address) {
                unconfirmed_rewards.push(json!({
                    "block_index": Value::Null,
                    "txid": tx.txid,
                    "vout": vout_index,
                    "zero_count": zero_count,
                    "reward": "unknown",
                    "address": address,
                }));
            }
        }
    }

    Ok(unconfirmed_rewards)
}

pub async fn rewards_by_address(
    Path(address): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<RewardsQuery>,
) -> ApiResult<impl IntoResponse> {
    let pool = state.sqlite_pool.clone();
    let offset = params.offset.unwrap_or(0);
    let limit = params
        .limit
        .unwrap_or(DEFAULT_REWARDS_LIMIT)
        .min(MAX_REWARDS_LIMIT);

    let order_clause = match params.sort.as_deref() {
        None | Some("") => {
            "block_index DESC, rowid DESC, reward DESC, zero_count DESC, txid ASC, vout ASC"
                .to_string()
        }
        Some("zero_count") => {
            "zero_count DESC, reward DESC, block_index DESC, rowid DESC, txid ASC, vout ASC"
                .to_string()
        }
        Some(other) => {
            eprintln!("unsupported rewards sort: {other}");
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_UNSUPPORTED_REWARD_SORT,
            ));
        }
    };

    // Fetch unconfirmed rewards if requested
    let all_unconfirmed = if params.unconfirmed {
        let base_url = state.electr_url.trim_end_matches('/');
        fetch_unconfirmed_rewards(&state.http_client, base_url, &address).await?
    } else {
        Vec::new()
    };

    let unconfirmed_count = all_unconfirmed.len();

    // Calculate pagination for unified results:
    // - Unconfirmed rewards come first (virtual positions 0..unconfirmed_count)
    // - Confirmed rewards follow (virtual positions unconfirmed_count..)
    let (unconfirmed_to_include, db_offset, db_limit) = if offset >= unconfirmed_count {
        // Offset is past all unconfirmed, only fetch from DB
        let db_offset = offset - unconfirmed_count;
        (Vec::new(), db_offset, limit)
    } else {
        // Include some unconfirmed rewards
        let unconfirmed_start = offset;
        let unconfirmed_end = (offset + limit).min(unconfirmed_count);
        let unconfirmed_slice = all_unconfirmed[unconfirmed_start..unconfirmed_end].to_vec();
        let remaining_limit = limit.saturating_sub(unconfirmed_slice.len());
        (unconfirmed_slice, 0, remaining_limit)
    };

    // Only query DB if we need confirmed rewards
    let confirmed_rewards = if db_limit > 0 {
        let db_offset_i64 = i64::try_from(db_offset).map_err(|_| {
            eprintln!("db_offset {db_offset} exceeds i64 range");
            json_error(StatusCode::BAD_REQUEST, ERR_OFFSET_RANGE)
        })?;
        let db_limit_i64 = db_limit as i64;

        spawn_blocking(move || {
            let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT block_index, txid, vout, zero_count, reward, address \
                     FROM rewards \
                     WHERE address = ?1 \
                     ORDER BY {order_clause} \
                     LIMIT ?2 OFFSET ?3"
                ))
                .map_err(|err| format!("prepare rewards-by-address statement: {err}"))?;

            let mapped = stmt
                .query_map(
                    rusqlite::params![address, db_limit_i64, db_offset_i64],
                    |row| {
                        Ok(json!({
                            "block_index": row.get::<_, i64>(0)?,
                            "txid": row.get::<_, String>(1)?,
                            "vout": row.get::<_, i64>(2)?,
                            "zero_count": row.get::<_, i64>(3)?,
                            "reward": row.get::<_, i64>(4)?,
                            "address": row.get::<_, Option<String>>(5)?,
                        }))
                    },
                )
                .map_err(|err| format!("query rewards-by-address map: {err}"))?;

            let rows = mapped
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|err| format!("collect rewards-by-address: {err}"))?;

            Ok::<_, String>(rows)
        })
        .await
        .map_err(|err| {
            eprintln!("failed to join sqlite task: {err}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
        })?
        .map_err(|err| {
            eprintln!("failed to fetch rewards by address: {err}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
        })?
    } else {
        Vec::new()
    };

    // Combine unconfirmed (first) and confirmed rewards
    let mut rewards = unconfirmed_to_include;
    rewards.extend(confirmed_rewards);

    if rewards.is_empty() {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            ERR_REWARD_NOT_FOUND_FOR_ADDRESS,
        ));
    }

    Ok(Json(rewards))
}

#[derive(Debug, Deserialize)]
pub struct RewardsCountQuery {
    #[serde(default)]
    unconfirmed: bool,
}

pub async fn rewards_count_by_address(
    Path(address): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<RewardsCountQuery>,
) -> ApiResult<impl IntoResponse> {
    let pool = state.sqlite_pool.clone();
    let address_clone = address.clone();

    // Query confirmed count and total from SQLite
    let (confirmed_count, total_confirmed) = spawn_blocking(move || {
        let conn = pool.get().map_err(|err| format!("get connection: {err}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT COUNT(*), COALESCE(SUM(reward), 0) \
                 FROM rewards \
                 WHERE address = ?1",
            )
            .map_err(|err| format!("prepare rewards-count statement: {err}"))?;

        let result = stmt
            .query_row([address_clone], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|err| format!("query rewards-count: {err}"))?;

        Ok::<_, String>(result)
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join sqlite task: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?
    .map_err(|err| {
        eprintln!("failed to fetch rewards count: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_SQLITE_FAILURE)
    })?;

    // Fetch unconfirmed count if requested
    let unconfirmed_count = if params.unconfirmed {
        let base_url = state.electr_url.trim_end_matches('/');
        let unconfirmed_rewards =
            fetch_unconfirmed_rewards(&state.http_client, base_url, &address).await?;
        unconfirmed_rewards.len() as i64
    } else {
        0
    };

    Ok(Json(json!({
        "confirmed_count": confirmed_count,
        "unconfirmed_count": unconfirmed_count,
        "total_confirmed": total_confirmed,
    })))
}

pub async fn address_utxos(
    Path(address): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let base_url = state.electr_url.trim_end_matches('/').to_string();
    let http_client = state.http_client.clone();

    let url = format!("{base_url}/address/{address}/utxo");
    let utxos: Vec<AddressUtxo> = http_client
        .get(url)
        .send()
        .await
        .map_err(|err| {
            eprintln!("failed to fetch UTXOs from electr for {address}: {err}");
            json_error(StatusCode::BAD_GATEWAY, ERR_ELECTRUM_FAILURE)
        })?
        .json()
        .await
        .map_err(|err| {
            eprintln!("failed to decode electr response for {address}: {err}");
            json_error(StatusCode::BAD_GATEWAY, ERR_ELECTRUM_FAILURE)
        })?;

    let confirmed_utxos: Vec<_> = utxos
        .into_iter()
        .filter(|utxo| utxo.status.confirmed)
        .collect();
    if confirmed_utxos.len() > MAX_ADDRESS_UTXOS {
        eprintln!(
            "too many confirmed UTXOs for {address}: {} > {MAX_ADDRESS_UTXOS}",
            confirmed_utxos.len()
        );
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_TOO_MANY_UTXOS_FOR_ADDRESS,
        ));
    }

    let mut parsed = Vec::with_capacity(confirmed_utxos.len());
    for utxo in confirmed_utxos {
        let txid = Txid::from_str(&utxo.txid).map_err(|err| {
            eprintln!("invalid txid {} from electr response: {err}", utxo.txid);
            json_error(StatusCode::BAD_GATEWAY, ERR_ELECTRUM_FAILURE)
        })?;
        parsed.push((txid, utxo.vout));
    }

    if parsed.is_empty() {
        return Ok(Json(Vec::<Value>::new()));
    }

    let mut balances = Vec::with_capacity(parsed.len());
    for chunk in parsed.chunks(ROLLBLOCK_BATCH_SIZE) {
        let chunk_balances =
            fetch_rollblock_balances(state.rollblock.clone(), chunk.to_vec()).await?;
        balances.extend(chunk_balances);
    }

    let response: Vec<Value> = balances
        .into_iter()
        .map(|(txid, vout, balance)| {
            json!({
                "txid": txid.to_string(),
                "vout": vout,
                "balance": balance,
            })
        })
        .collect();

    Ok(Json(response))
}

pub async fn utxo_balance(
    Path(outpoint): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let (txid_str, vout_str) = outpoint
        .split_once(':')
        .ok_or(json_error(StatusCode::BAD_REQUEST, ERR_MALFORMED_OUTPOINT))?;

    let txid = Txid::from_str(txid_str).map_err(|err| {
        eprintln!("invalid txid {txid_str}: {err}");
        json_error(StatusCode::BAD_REQUEST, ERR_MALFORMED_OUTPOINT)
    })?;
    let vout: u32 = vout_str.parse().map_err(|err| {
        eprintln!("invalid vout {vout_str}: {err}");
        json_error(StatusCode::BAD_REQUEST, ERR_MALFORMED_OUTPOINT)
    })?;

    let mut balances =
        fetch_rollblock_balances(state.rollblock.clone(), vec![(txid, vout)]).await?;
    let (txid, vout, balance) = balances
        .pop()
        .unwrap_or_else(|| unreachable!("rollblock balance list matches input length"));

    Ok(Json(json!({
        "txid": txid.to_string(),
        "vout": vout,
        "balance": balance,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UtxoBatchRequest {
    pub utxos: Vec<String>,
}

pub async fn utxo_balances(
    State(state): State<AppState>,
    Json(body): Json<UtxoBatchRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.utxos.len() > 100 {
        eprintln!("too many utxos requested: {}", body.utxos.len());
        return Err(json_error(StatusCode::BAD_REQUEST, ERR_TOO_MANY_OUTPOINTS));
    }

    let mut parsed = Vec::with_capacity(body.utxos.len());
    for outpoint in body.utxos {
        let (txid_str, vout_str) = outpoint
            .split_once(':')
            .ok_or(json_error(StatusCode::BAD_REQUEST, ERR_TOO_MANY_OUTPOINTS))?;

        let txid = Txid::from_str(txid_str).map_err(|err| {
            eprintln!("invalid txid {txid_str}: {err}");
            json_error(StatusCode::BAD_REQUEST, ERR_TOO_MANY_OUTPOINTS)
        })?;
        let vout: u32 = vout_str.parse().map_err(|err| {
            eprintln!("invalid vout {vout_str}: {err}");
            json_error(StatusCode::BAD_REQUEST, ERR_TOO_MANY_OUTPOINTS)
        })?;

        parsed.push((txid, vout));
    }

    if parsed.is_empty() {
        return Ok(Json(Vec::<Value>::new()));
    }

    let balances = fetch_rollblock_balances(state.rollblock.clone(), parsed).await?;

    let response: Vec<Value> = balances
        .into_iter()
        .map(|(txid, vout, balance)| {
            json!({
                "txid": txid.to_string(),
                "vout": vout,
                "balance": balance,
            })
        })
        .collect();

    Ok(Json(response))
}

async fn fetch_rollblock_balances(
    rollblock: RollblockPool,
    outpoints: Vec<(Txid, u32)>,
) -> ApiResult<Vec<(Txid, u32, u64)>> {
    if outpoints.is_empty() {
        return Ok(Vec::new());
    }

    let keys: Vec<StoreKey> = outpoints
        .iter()
        .map(|(txid, vout)| StoreKey::from_prefix(compute_utxo_key(txid, *vout)))
        .collect();

    let mut values = spawn_blocking(move || {
        let mut client = rollblock.connect()?;
        let values = client
            .get(&keys)
            .map_err(|err| format!("get batch: {err}"))?;
        client.close().map_err(|err| format!("close: {err}"))?;
        Ok::<_, String>(values)
    })
    .await
    .map_err(|err| {
        eprintln!("failed to join rollblock task: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_ROLLBLOCK_FAILURE)
    })?
    .map_err(|err| {
        eprintln!("rollblock request failed: {err}");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, ERR_ROLLBLOCK_FAILURE)
    })?;

    // Ensure we always return one balance per outpoint, defaulting to zero when missing.
    if values.len() < outpoints.len() {
        values.resize(outpoints.len(), Vec::new());
    }

    outpoints
        .into_iter()
        .zip(values.into_iter())
        .map(|((txid, vout), value)| decode_balance(value).map(|balance| (txid, vout, balance)))
        .collect()
}

/// Decodes a rollblock balance value.
///
/// Since zeldhash-protocol v0.6.0, spent UTXOs are retained as negative tombstones.
/// This function treats negative balances as zero (spent UTXO).
fn decode_balance(value: Vec<u8>) -> ApiResult<u64> {
    match value.len() {
        0 => Ok(0u64),
        8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&value);
            let signed = i64::from_le_bytes(buf);
            // Negative balance indicates a spent UTXO (tombstone); treat as zero.
            Ok(signed.max(0) as u64)
        }
        other => {
            eprintln!("invalid value length from rollblock: {other}");
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_ROLLBLOCK_FAILURE,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rollblockpool::{build_rollblock_client_settings, MockRemoteStoreClient, RollblockPool},
        sqlitepool::SqlitePool,
        AppState,
    };
    use axum::body::to_bytes;
    use axum::{
        extract::{Path, Query, State},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use bitcoin::hashes::Hash;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use reqwest::Client;
    use rusqlite::Connection;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    /// (block_index, txid, vout, zero_count, reward, address)
    type RewardRow<'a> = (i64, &'a str, i64, i64, i64, Option<&'a str>);

    fn build_sqlite_pool_with_data(
        stats_rows: Vec<(i64, &str, &str)>,
        rewards_rows: Vec<RewardRow<'_>>,
    ) -> (SqlitePool, tempfile::TempDir) {
        let tmp = tempdir().expect("temp dir");
        let db_path = tmp.path().join("test.sqlite");

        let conn = Connection::open(&db_path).expect("create sqlite db");
        conn.execute(
            "CREATE TABLE stats (block_index INTEGER PRIMARY KEY, block_stats TEXT NOT NULL, cumul_stats TEXT NOT NULL)",
            [],
        )
        .expect("create stats table");
        conn.execute(
            "CREATE TABLE rewards (block_index INTEGER, txid TEXT, vout INTEGER, zero_count INTEGER, reward INTEGER, address TEXT)",
            [],
        )
        .expect("create rewards table");

        for (block_index, block_stats, cumul_stats) in stats_rows {
            conn.execute(
                "INSERT INTO stats (block_index, block_stats, cumul_stats) VALUES (?1, ?2, ?3)",
                (block_index, block_stats, cumul_stats),
            )
            .expect("insert stats row");
        }

        for (block_index, txid, vout, zero_count, reward, address) in rewards_rows {
            conn.execute(
                "INSERT INTO rewards (block_index, txid, vout, zero_count, reward, address) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (block_index, txid, vout, zero_count, reward, address),
            )
            .expect("insert reward row");
        }

        let manager = SqliteConnectionManager::file(&db_path);
        let pool = Pool::builder()
            .max_size(4)
            .build(manager)
            .expect("build sqlite pool");

        (pool, tmp)
    }

    fn failing_sqlite_pool() -> SqlitePool {
        let manager = SqliteConnectionManager::file("/root/forbidden.sqlite");
        Pool::builder()
            .test_on_check_out(false)
            .build_unchecked(manager)
    }

    fn default_http_client() -> Client {
        Client::builder().build().expect("http client")
    }

    fn mock_rollblock_pool_with_responses(responses: Vec<Vec<Vec<u8>>>) -> RollblockPool {
        let mock = MockRemoteStoreClient::new();
        for response in responses {
            mock.push_response(response);
        }
        let settings = build_rollblock_client_settings("mock", 1, "user", "pass");
        RollblockPool::with_mock(settings, mock)
    }

    fn sample_state(pool: SqlitePool, rollblock: RollblockPool, electr_url: String) -> AppState {
        AppState {
            sqlite_pool: pool,
            rollblock,
            electr_url,
            http_client: default_http_client(),
        }
    }

    fn sample_txid(n: u8) -> (String, Txid) {
        let mut bytes = [n; 32];
        bytes[0] = n;
        let txid = Txid::from_byte_array(bytes);
        (txid.to_string(), txid)
    }

    async fn response_json(response: impl IntoResponse) -> Value {
        let response = response.into_response();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&body).expect("parse json")
    }

    async fn spawn_mock_electr_server(body: serde_json::Value) -> (String, oneshot::Sender<()>) {
        let app = Router::new().route(
            "/address/{address}/utxo",
            get(move || {
                let payload = body.clone();
                async move { Json(payload) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock electr");
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        (format!("http://{}", addr), shutdown_tx)
    }

    #[tokio::test]
    async fn root_returns_ok() {
        let (pool, _tmp) =
            build_sqlite_pool_with_data(vec![(1, r#"{"height":1}"#, r#"{"cumul":1}"#)], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let response = root(State(state))
            .await
            .expect("root success")
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn root_returns_error_when_sqlite_unavailable() {
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(failing_sqlite_pool(), rollblock, "http://localhost".into());

        let result = root(State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected root error");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], ERR_SQLITE_OR_ROLLBLOCK_UNAVAILABLE);
    }

    #[tokio::test]
    async fn blocks_returns_cumul_stats() {
        let (pool, _tmp) =
            build_sqlite_pool_with_data(vec![(5, r#"{"height":5}"#, r#"{"total":10}"#)], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let stats = response_json(blocks(State(state)).await.expect("blocks success")).await;
        assert_eq!(stats["total"], 10);
    }

    #[tokio::test]
    async fn blocks_fails_on_invalid_json() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "{}", "not-json")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = blocks(State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected blocks error");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], ERR_INVALID_JSON_OR_SQLITE_FAILURE);
    }

    #[tokio::test]
    async fn block_details_returns_stats_and_rewards() {
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(7, r#"{"block":7}"#, r#"{"agg":70}"#)],
            vec![
                (7, "aaa", 0, 2, 50, Some("addr1")),
                (7, "bbb", 1, 3, 25, Some("addr2")),
            ],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let body = response_json(
            block_details(Path(7), State(state))
                .await
                .expect("block details success"),
        )
        .await;
        assert_eq!(body["block_index"], 7);
        assert_eq!(body["rewards"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn block_details_returns_not_found() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = block_details(Path(42), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected block not found error");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], ERR_BLOCK_NOT_FOUND);
    }

    #[tokio::test]
    async fn block_details_rejects_overflow_height() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = block_details(Path(u64::MAX), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected block height overflow error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_BLOCK_HEIGHT_RANGE);
    }

    #[tokio::test]
    async fn block_details_fails_on_bad_json() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "bad-json", "{}")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = block_details(Path(1), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected invalid block JSON error");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], ERR_INVALID_JSON_OR_SQLITE_FAILURE);
    }

    #[tokio::test]
    async fn rewards_applies_limit_and_offset() {
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(1, "{}", "{}")],
            vec![
                (1, "tx1", 0, 1, 10, None),
                (2, "tx2", 1, 1, 9, None),
                (3, "tx3", 2, 1, 8, None),
            ],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsQuery {
            offset: Some(1),
            limit: Some(MAX_REWARDS_LIMIT + 10),
            sort: None,
            unconfirmed: false,
        };

        let list = response_json(
            rewards(State(state), Query(query))
                .await
                .expect("rewards ok"),
        )
        .await;
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["txid"], "tx2");
    }

    #[tokio::test]
    async fn rewards_rejects_overflow_offset() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "{}", "{}")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsQuery {
            offset: Some(usize::MAX),
            limit: None,
            sort: None,
            unconfirmed: false,
        };

        let result = rewards(State(state), Query(query)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected rewards offset error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_OFFSET_RANGE);
    }

    #[tokio::test]
    async fn rewards_supports_zero_count_sort() {
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(1, "{}", "{}")],
            vec![
                (1, "tx1", 0, 3, 50, None),
                (2, "tx2", 0, 5, 40, None),
                (3, "tx3", 0, 5, 30, None),
                (4, "tx4", 0, 1, 100, None),
            ],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsQuery {
            offset: None,
            limit: None,
            sort: Some("zero_count".into()),
            unconfirmed: false,
        };

        let list = response_json(
            rewards(State(state), Query(query))
                .await
                .expect("rewards ok"),
        )
        .await;
        let arr = list.as_array().unwrap();
        assert_eq!(arr[0]["txid"], "tx2");
        assert_eq!(arr[1]["txid"], "tx3");
        assert_eq!(arr[2]["txid"], "tx1");
        assert_eq!(arr[3]["txid"], "tx4");
    }

    #[tokio::test]
    async fn rewards_rejects_invalid_sort() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "{}", "{}")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsQuery {
            offset: None,
            limit: None,
            sort: Some("bad".into()),
            unconfirmed: false,
        };

        let result = rewards(State(state), Query(query)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected rewards invalid sort error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_UNSUPPORTED_REWARD_SORT);
    }

    #[tokio::test]
    async fn rewards_by_txid_returns_rows() {
        let (txid_str, _txid) = sample_txid(1);
        let other_txid = sample_txid(2).0;
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(1, "{}", "{}")],
            vec![
                (7, &txid_str, 0, 3, 100, Some("addr1")),
                (6, &txid_str, 1, 2, 50, Some("addr2")),
                (5, &other_txid, 0, 1, 25, None),
            ],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let response = response_json(
            rewards_by_txid(Path(txid_str.clone()), State(state))
                .await
                .expect("rewards by txid ok"),
        )
        .await;
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["block_index"], 7);
        assert_eq!(arr[1]["vout"], 1);
    }

    #[tokio::test]
    async fn rewards_by_txid_returns_not_found() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "{}", "{}")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let (txid_str, _txid) = sample_txid(3);

        let result = rewards_by_txid(Path(txid_str), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected rewards by txid not found");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], ERR_REWARD_NOT_FOUND);
    }

    #[tokio::test]
    async fn rewards_by_txid_rejects_invalid_txid() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![(1, "{}", "{}")], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = rewards_by_txid(Path("not-a-txid".into()), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected malformed txid error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_MALFORMED_TXID);
    }

    #[tokio::test]
    async fn address_utxos_filters_unconfirmed_and_fetches_balances() {
        let utxo_body = json!([
            { "txid": "11".repeat(32), "vout": 0, "status": { "confirmed": true } },
            { "txid": "22".repeat(32), "vout": 1, "status": { "confirmed": false } }
        ]);
        let (base_url, shutdown) = spawn_mock_electr_server(utxo_body).await;
        let rollblock =
            mock_rollblock_pool_with_responses(vec![vec![123u64.to_le_bytes().to_vec()]]);
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let state = sample_state(pool, rollblock, base_url);

        let response = response_json(
            address_utxos(Path("addr".into()), State(state))
                .await
                .expect("address utxos ok"),
        )
        .await;

        shutdown.send(()).ok();
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["balance"], 123);
    }

    #[tokio::test]
    async fn address_utxos_returns_empty_when_no_confirmed() {
        let utxo_body = json!([
            { "txid": "33".repeat(32), "vout": 0, "status": { "confirmed": false } }
        ]);
        let (base_url, shutdown) = spawn_mock_electr_server(utxo_body).await;
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, base_url);

        let response = response_json(
            address_utxos(Path("addr".into()), State(state))
                .await
                .expect("address utxos ok"),
        )
        .await;
        shutdown.send(()).ok();
        assert!(response.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn address_utxos_rejects_over_limit() {
        let utxo_body = serde_json::Value::Array(
            (0..=MAX_ADDRESS_UTXOS)
                .map(|i| {
                    json!({
                        "txid": format!("{:02x}", i).repeat(32),
                        "vout": 0,
                        "status": { "confirmed": true }
                    })
                })
                .collect(),
        );
        let (base_url, shutdown) = spawn_mock_electr_server(utxo_body).await;
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, base_url);

        let result = address_utxos(Path("addr".into()), State(state)).await;
        shutdown.send(()).ok();
        let Err((status, Json(body))) = result else {
            panic!("expected too many utxos error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_TOO_MANY_UTXOS_FOR_ADDRESS);
    }

    #[tokio::test]
    async fn utxo_balance_returns_balance() {
        let (txid_str, _txid) = sample_txid(3);
        let outpoint = format!("{txid_str}:0");
        let rollblock =
            mock_rollblock_pool_with_responses(vec![vec![999u64.to_le_bytes().to_vec()]]);
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let body = response_json(
            utxo_balance(Path(outpoint), State(state))
                .await
                .expect("utxo balance ok"),
        )
        .await;

        assert_eq!(body["balance"], 999);
    }

    #[tokio::test]
    async fn utxo_balance_rejects_invalid_txid() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());

        let result = utxo_balance(Path("notatxid:0".into()), State(state)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected malformed outpoint error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_MALFORMED_OUTPOINT);
    }

    #[tokio::test]
    async fn utxo_balances_rejects_too_many() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let payload = UtxoBatchRequest {
            utxos: vec!["00".repeat(32) + ":0"; 101],
        };

        let result = utxo_balances(State(state), Json(payload)).await;
        let Err((status, Json(body))) = result else {
            panic!("expected too many outpoints error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], ERR_TOO_MANY_OUTPOINTS);
    }

    #[tokio::test]
    async fn utxo_balances_returns_empty_for_no_inputs() {
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let payload = UtxoBatchRequest { utxos: vec![] };

        let response = response_json(
            utxo_balances(State(state), Json(payload))
                .await
                .expect("utxo balances ok"),
        )
        .await;
        assert!(response.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn utxo_balances_parses_and_returns_values() {
        let (txid1, _txid_obj1) = sample_txid(4);
        let (txid2, _txid_obj2) = sample_txid(5);
        let rollblock = mock_rollblock_pool_with_responses(vec![vec![
            7u64.to_le_bytes().to_vec(),
            8u64.to_le_bytes().to_vec(),
        ]]);
        let (pool, _tmp) = build_sqlite_pool_with_data(vec![], vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let payload = UtxoBatchRequest {
            utxos: vec![format!("{txid1}:0"), format!("{txid2}:1")],
        };

        let response = response_json(
            utxo_balances(State(state), Json(payload))
                .await
                .expect("utxo balances ok"),
        )
        .await;
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["balance"], 7);
        assert_eq!(arr[1]["balance"], 8);
    }

    #[tokio::test]
    async fn fetch_rollblock_balances_resizes_missing_values() {
        let (_txid_str1, txid1) = sample_txid(6);
        let (txid_str2, _txid2) = sample_txid(7);
        let rollblock = mock_rollblock_pool_with_responses(vec![vec![1u64.to_le_bytes().to_vec()]]);
        let outpoints = vec![(txid1, 0), (Txid::from_str(&txid_str2).unwrap(), 1)];

        let balances = fetch_rollblock_balances(rollblock, outpoints)
            .await
            .expect("fetch balances");
        assert_eq!(balances.len(), 2);
        assert_eq!(balances[0].2, 1);
        assert_eq!(balances[1].2, 0);
    }

    #[tokio::test]
    async fn fetch_rollblock_balances_returns_error_on_rollblock_failure() {
        let settings = build_rollblock_client_settings("mock", 1, "user", "pass");
        let rollblock = RollblockPool::new(settings);
        let (txid_str, txid) = sample_txid(7);
        let outpoints = vec![(txid, 0), (Txid::from_str(&txid_str).unwrap(), 1)];

        let result = fetch_rollblock_balances(rollblock, outpoints).await;
        let Err((status, Json(body))) = result else {
            panic!("expected rollblock failure");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], ERR_ROLLBLOCK_FAILURE);
    }

    #[test]
    fn decode_balance_handles_lengths() {
        assert_eq!(decode_balance(Vec::new()).unwrap(), 0);
        assert_eq!(decode_balance(42u64.to_le_bytes().to_vec()).unwrap(), 42);
        let Err((status, Json(body))) = decode_balance(vec![1, 2, 3, 4]) else {
            panic!("expected rollblock decode failure");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], ERR_ROLLBLOCK_FAILURE);
    }

    #[test]
    fn decode_balance_treats_negative_as_zero() {
        // Negative balance (spent UTXO tombstone) should be treated as zero.
        assert_eq!(decode_balance((-1i64).to_le_bytes().to_vec()).unwrap(), 0);
        assert_eq!(decode_balance((-100i64).to_le_bytes().to_vec()).unwrap(), 0);
        assert_eq!(decode_balance(i64::MIN.to_le_bytes().to_vec()).unwrap(), 0);
        // Positive values should pass through unchanged.
        assert_eq!(decode_balance(100i64.to_le_bytes().to_vec()).unwrap(), 100);
    }

    #[test]
    fn compute_utxo_key_is_stable() {
        let (_, txid) = sample_txid(9);
        let key1 = compute_utxo_key(&txid, 0);
        let key2 = compute_utxo_key(&txid, 0);
        let key3 = compute_utxo_key(&txid, 1);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn rewards_count_by_address_returns_counts() {
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(1, "{}", "{}")],
            vec![
                (1, "tx1", 0, 3, 100, Some("addr1")),
                (2, "tx2", 0, 5, 200, Some("addr1")),
                (3, "tx3", 0, 2, 50, Some("addr2")),
            ],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsCountQuery { unconfirmed: false };

        let body = response_json(
            rewards_count_by_address(Path("addr1".into()), State(state), Query(query))
                .await
                .expect("rewards count ok"),
        )
        .await;

        assert_eq!(body["confirmed_count"], 2);
        assert_eq!(body["unconfirmed_count"], 0);
        assert_eq!(body["total_confirmed"], 300);
    }

    #[tokio::test]
    async fn rewards_count_by_address_returns_zero_for_unknown_address() {
        let (pool, _tmp) = build_sqlite_pool_with_data(
            vec![(1, "{}", "{}")],
            vec![(1, "tx1", 0, 3, 100, Some("addr1"))],
        );
        let rollblock = mock_rollblock_pool_with_responses(vec![]);
        let state = sample_state(pool, rollblock, "http://localhost".into());
        let query = RewardsCountQuery { unconfirmed: false };

        let body = response_json(
            rewards_count_by_address(Path("unknown".into()), State(state), Query(query))
                .await
                .expect("rewards count ok"),
        )
        .await;

        assert_eq!(body["confirmed_count"], 0);
        assert_eq!(body["unconfirmed_count"], 0);
        assert_eq!(body["total_confirmed"], 0);
    }
}
