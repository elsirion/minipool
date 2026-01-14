use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use axum::middleware;
use axum::routing::MethodRouter;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use bitcoincore_rpc::bitcoin::{
    consensus::deserialize, consensus::serialize, BlockHash, Transaction, Txid,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::Parser;
use serde::Serialize;
use std::convert::Infallible;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use self::metrics::track_metrics;

mod metrics;

/// Confirmation targets for fee estimation offered by mempool.space and blockstream.info
const CONFIRMATION_TARGETS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 144,
    504, 1008,
];

/// Maximum transaction hex size (~400KB transaction = 800KB hex)
/// Bitcoin consensus limit is 400KB for standard transactions
const MAX_TX_HEX_SIZE: usize = 800_000;

/// Check if an RPC error indicates a "not found" condition
fn is_not_found_error(e: &bitcoincore_rpc::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("not found")
        || msg.contains("no such")
        || msg.contains("block height out of range")
        || msg.contains("not yet in block")
}

/// Handle RPC errors consistently, distinguishing "not found" from other errors
fn handle_rpc_error(
    e: bitcoincore_rpc::Error,
    resource_type: &str,
    resource_id: &str,
) -> (StatusCode, &'static str) {
    if is_not_found_error(&e) {
        warn!("{} not found {}: {}", resource_type, resource_id, e);
        match resource_type {
            "Block" => (StatusCode::NOT_FOUND, "Block not found"),
            "Transaction" => (StatusCode::NOT_FOUND, "Transaction not found"),
            _ => (StatusCode::NOT_FOUND, "Resource not found"),
        }
    } else {
        warn!("RPC error getting {} {}: {}", resource_type, resource_id, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "RPC error")
    }
}

/// Handle task join errors (panics/cancellations)
fn handle_task_error<E: std::fmt::Display>(e: E, operation: &str) -> (StatusCode, &'static str) {
    warn!("Task failed during {}: {}", operation, e);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

/// Esplora-compatible transaction status
#[derive(Serialize)]
struct TxStatus {
    confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_time: Option<u64>,
}

impl TxStatus {
    /// Build TxStatus from transaction info and block height
    fn from_tx_info(
        tx_info: &bitcoincore_rpc::json::GetRawTransactionResult,
        block_height: Option<u64>,
    ) -> Self {
        if let Some(block_hash) = &tx_info.blockhash {
            TxStatus {
                confirmed: true,
                block_height,
                block_hash: Some(block_hash.to_string()),
                block_time: tx_info.blocktime.map(|t| t as u64),
            }
        } else {
            TxStatus {
                confirmed: false,
                block_height: None,
                block_hash: None,
                block_time: None,
            }
        }
    }
}

/// Esplora-compatible transaction input
#[derive(Serialize)]
struct TxVin {
    txid: String,
    vout: u32,
    scriptsig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptsig_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<Vec<String>>,
    sequence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    prevout: Option<TxPrevout>,
    is_coinbase: bool,
}

/// Previous output information
#[derive(Serialize)]
struct TxPrevout {
    scriptpubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_address: Option<String>,
    value: u64,
}

/// Esplora-compatible transaction output
#[derive(Serialize)]
struct TxVout {
    scriptpubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scriptpubkey_address: Option<String>,
    value: u64,
}

/// Esplora-compatible transaction response
#[derive(Serialize)]
struct TxResponse {
    txid: String,
    version: i32,
    locktime: u32,
    size: usize,
    weight: usize,
    /// Fee in satoshis. None when prevout data is unavailable to calculate it.
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
    vin: Vec<TxVin>,
    vout: Vec<TxVout>,
    status: TxStatus,
}

/// Esplora-compatible merkle proof response
#[derive(Serialize)]
struct MerkleProofResponse {
    block_height: u64,
    merkle: Vec<String>,
    pos: usize,
}

/// Esplora-compatible block response
#[derive(Serialize)]
struct BlockResponse {
    id: String,
    height: u64,
    version: i32,
    timestamp: u64,
    bits: u32,
    nonce: u32,
    merkle_root: String,
    tx_count: usize,
    size: usize,
    weight: usize,
    previousblockhash: Option<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// Bitcoin RPC URL
    #[arg(long, env = "BITCOIN_RPC_URL")]
    bitcoin_rpc_url: String,

    /// Bitcoin RPC username
    #[arg(long, env = "BITCOIN_RPC_USER")]
    bitcoin_rpc_user: String,

    /// Bitcoin RPC password
    #[arg(long, env = "BITCOIN_RPC_PASS")]
    bitcoin_rpc_pass: String,

    /// Bind address for the HTTP server
    #[arg(long, env = "BIND_ADDR", default_value = "127.0.0.1:3000")]
    bind_addr: SocketAddr,

    #[arg(
        long,
        env = "PROMETHEUS_BIND_ADDR",
        default_value = "[::]:3001",
        help = "Prometheus address to bind/listen to"
    )]
    prometheus_bind_addr: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    rpc: Arc<Client>,
    routes: Arc<Vec<RouteInfo>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::parse();
    info!(
        "Starting minipool with config: bitcoin-rpc-user={:?}, bitcoin-rpc-url={:?}",
        config.bitcoin_rpc_user, config.bitcoin_rpc_url
    );

    let metrics_server = metrics::start_metrics_server(config.prometheus_bind_addr);
    let main_server = start_main_server(config);

    tokio::try_join!(metrics_server, main_server)?;
    Ok(())
}

async fn start_main_server(config: Config) -> Result<()> {
    let rpc = Client::new(
        &config.bitcoin_rpc_url,
        Auth::UserPass(config.bitcoin_rpc_user, config.bitcoin_rpc_pass),
    )?;

    let routes = vec![
        RouteInfo::new("/health", "Useful for health check", get(get_tip_height)),
        RouteInfo::new(
            "/api/blocks/tip/height",
            "Get the current blockchain tip height.",
            get(get_tip_height),
        ),
        RouteInfo::new(
            "/api/blocks/tip/hash",
            "Get the best block hash.",
            get(get_tip_hash),
        ),
        RouteInfo::new(
            "/api/block-height/{height}",
            "Get the block hash for a specific height.",
            get(get_block_by_height),
        ),
        RouteInfo::new(
            "/api/fee-estimates",
            "Get fee estimates for different confirmation targets.",
            get(get_fee_estimates),
        ),
        RouteInfo::new(
            "/api/block/{hash}/raw",
            "Get the raw block data for a specific block hash.",
            get(get_block_raw),
        ),
        RouteInfo::new(
            "/api/block/{hash}/header",
            "Get the block header as hex for a specific block hash.",
            get(get_block_header),
        ),
        RouteInfo::new(
            "/api/block/{hash}",
            "Get block information for a specific block hash.",
            get(get_block_info),
        ),
        RouteInfo::new(
            "/api/tx/{txid}",
            "Get transaction information for a specific txid.",
            get(get_transaction),
        ),
        RouteInfo::new(
            "/api/tx/{txid}/status",
            "Get transaction confirmation status.",
            get(get_tx_status),
        ),
        RouteInfo::new(
            "/api/tx/{txid}/merkle-proof",
            "Get merkle proof for a transaction (JSON format).",
            get(get_tx_merkle_proof),
        ),
        RouteInfo::new(
            "/api/tx/{txid}/merkleblock-proof",
            "Get merkle inclusion proof for a transaction (binary format).",
            get(get_tx_merkleblock_proof),
        ),
        RouteInfo::new_post(
            "/api/tx",
            "Broadcast a raw transaction (hex-encoded in body).",
            post(broadcast_transaction),
        ),
    ];

    let state = AppState {
        rpc: Arc::new(rpc),
        routes: Arc::new(routes.clone()),
    };

    let mut app = Router::new().route("/", get(index));

    // Add all routes from the routes vec
    for route in routes {
        app = app.route(route.path, route.handler);
    }

    let app = app
        .fallback(fallback)
        .layer(TraceLayer::new_for_http())
        .route_layer(middleware::from_fn(track_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!("Listening on {}", config.bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_tip_height(State(state): State<AppState>) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || rpc.get_block_count()).await {
        Ok(Ok(height)) => (StatusCode::OK, height.to_string()).into_response(),
        Ok(Err(e)) => {
            warn!("RPC error getting tip height: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
        Err(e) => handle_task_error(e, "get tip height").into_response(),
    }
}

/// GET /api/blocks/tip/hash - Get the best block hash
async fn get_tip_hash(State(state): State<AppState>) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || rpc.get_best_block_hash()).await {
        Ok(Ok(hash)) => (StatusCode::OK, hash.to_string()).into_response(),
        Ok(Err(e)) => {
            warn!("RPC error getting tip hash: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
        Err(e) => handle_task_error(e, "get tip hash").into_response(),
    }
}

async fn get_block_by_height(
    State(state): State<AppState>,
    Path(height): Path<u64>,
) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || rpc.get_block_hash(height)).await {
        Ok(Ok(hash)) => (StatusCode::OK, hash.to_string()).into_response(),
        Ok(Err(e)) => handle_rpc_error(e, "Block", &height.to_string()).into_response(),
        Err(e) => handle_task_error(e, "get block by height").into_response(),
    }
}

/// Convert fee rate from Bitcoin Core format (BTC/kB) to esplora format (sat/vB)
fn btc_per_kb_to_sat_per_vb(fee_rate: bitcoincore_rpc::bitcoin::Amount) -> f64 {
    // BTC/kB to sat/vB: multiply by 100_000_000 (sats/BTC), divide by 1000 (bytes/kB)
    // Simplified: sat/kB / 1000 = sat/vB
    fee_rate.to_sat() as f64 / 1000.0
}

fn get_fee_rate_blocking(rpc: &Client, blocks: u16) -> Result<Option<f64>, bitcoincore_rpc::Error> {
    let estimate = rpc.estimate_smart_fee(blocks, None)?;
    Ok(estimate.fee_rate.map(btc_per_kb_to_sat_per_vb))
}

async fn get_fee_estimates(State(state): State<AppState>) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || {
        let estimates: BTreeMap<String, f64> = CONFIRMATION_TARGETS
            .iter()
            .filter_map(|&blocks| {
                match get_fee_rate_blocking(&rpc, blocks) {
                    Ok(Some(fee)) => Some((blocks.to_string(), fee)),
                    Ok(None) => None, // No estimate available, skip this target
                    Err(e) => {
                        warn!("Error getting fee estimate for {} blocks: {}", blocks, e);
                        None
                    }
                }
            })
            .collect();
        Ok::<_, bitcoincore_rpc::Error>(estimates)
    })
    .await
    {
        Ok(Ok(estimates)) => Json(estimates).into_response(),
        Ok(Err(e)) => {
            warn!("RPC error getting fee estimates: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
        Err(e) => handle_task_error(e, "get fee estimates").into_response(),
    }
}

async fn get_block_raw(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match BlockHash::from_str(&hash) {
        Ok(block_hash) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || rpc.get_block(&block_hash)).await {
                Ok(Ok(block)) => {
                    let bytes = serialize(&block);
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        bytes,
                    )
                        .into_response()
                }
                Ok(Err(e)) => handle_rpc_error(e, "Block", &hash).into_response(),
                Err(e) => handle_task_error(e, "get raw block").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid block hash: {}: {}", hash, e);
            (StatusCode::BAD_REQUEST, "Invalid block hash").into_response()
        }
    }
}

/// GET /api/block/{hash}/header - Get block header as hex
async fn get_block_header(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match BlockHash::from_str(&hash) {
        Ok(block_hash) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || rpc.get_block_header(&block_hash)).await {
                Ok(Ok(header)) => {
                    let header_bytes = serialize(&header);
                    (StatusCode::OK, hex::encode(header_bytes)).into_response()
                }
                Ok(Err(e)) => handle_rpc_error(e, "Block", &hash).into_response(),
                Err(e) => handle_task_error(e, "get block header").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid block hash: {}: {}", hash, e);
            (StatusCode::BAD_REQUEST, "Invalid block hash").into_response()
        }
    }
}

/// GET /api/block/{hash} - Get block information in esplora format
async fn get_block_info(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match BlockHash::from_str(&hash) {
        Ok(block_hash) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || {
                let block_info = rpc.get_block_info(&block_hash)?;
                let block_header = rpc.get_block_header(&block_hash)?;
                Ok::<_, bitcoincore_rpc::Error>((block_info, block_header))
            })
            .await
            {
                Ok(Ok((info, header))) => {
                    let response = BlockResponse {
                        id: info.hash.to_string(),
                        height: info.height as u64,
                        version: header.version.to_consensus(),
                        timestamp: header.time as u64,
                        bits: header.bits.to_consensus(),
                        nonce: header.nonce,
                        merkle_root: header.merkle_root.to_string(),
                        tx_count: info.n_tx,
                        size: info.size,
                        weight: info.weight,
                        previousblockhash: info.previousblockhash.map(|h| h.to_string()),
                    };
                    Json(response).into_response()
                }
                Ok(Err(e)) => handle_rpc_error(e, "Block", &hash).into_response(),
                Err(e) => handle_task_error(e, "get block info").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid block hash: {}: {}", hash, e);
            (StatusCode::BAD_REQUEST, "Invalid block hash").into_response()
        }
    }
}

/// GET /api/tx/{txid} - Get transaction information in esplora format
async fn get_transaction(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> impl IntoResponse {
    match Txid::from_str(&txid) {
        Ok(tx_id) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || {
                let tx_info = rpc.get_raw_transaction_info(&tx_id, None)?;
                // If transaction is confirmed, also get block height
                let block_height = if let Some(ref block_hash) = tx_info.blockhash {
                    rpc.get_block_header_info(block_hash)
                        .ok()
                        .map(|info| info.height as u64)
                } else {
                    None
                };
                Ok::<_, bitcoincore_rpc::Error>((tx_info, block_height))
            })
            .await
            {
                Ok(Ok((tx_info, block_height))) => {
                    // Build esplora-compatible response
                    let status = TxStatus::from_tx_info(&tx_info, block_height);

                    // Build vin array
                    let vin: Vec<TxVin> = tx_info
                        .vin
                        .iter()
                        .map(|input| {
                            let is_coinbase = input.coinbase.is_some();
                            TxVin {
                                txid: input
                                    .txid
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "0".repeat(64)),
                                vout: input.vout.unwrap_or(0),
                                scriptsig: input
                                    .script_sig
                                    .as_ref()
                                    .map(|s| hex::encode(&s.hex))
                                    .unwrap_or_default(),
                                scriptsig_asm: input.script_sig.as_ref().map(|s| s.asm.clone()),
                                witness: input
                                    .txinwitness
                                    .as_ref()
                                    .map(|w| w.iter().map(hex::encode).collect()),
                                sequence: input.sequence,
                                prevout: None, // Would require additional RPC calls to fetch
                                is_coinbase,
                            }
                        })
                        .collect();

                    // Build vout array
                    let vout: Vec<TxVout> = tx_info
                        .vout
                        .iter()
                        .map(|output| TxVout {
                            scriptpubkey: hex::encode(&output.script_pub_key.hex),
                            scriptpubkey_asm: Some(output.script_pub_key.asm.clone()),
                            scriptpubkey_type: output
                                .script_pub_key
                                .type_
                                .as_ref()
                                .map(|t| format!("{:?}", t).to_lowercase()),
                            scriptpubkey_address: output
                                .script_pub_key
                                .address
                                .as_ref()
                                .map(|a| a.clone().assume_checked().to_string()),
                            value: output.value.to_sat(),
                        })
                        .collect();

                    // Calculate actual weight by deserializing the raw transaction (BIP-141)
                    let weight = match deserialize::<Transaction>(&tx_info.hex) {
                        Ok(tx) => tx.weight().to_wu() as usize,
                        Err(e) => {
                            warn!(
                                "Failed to deserialize tx {} for weight calculation: {}. Using vsize approximation.",
                                tx_info.txid, e
                            );
                            tx_info.vsize * 4
                        }
                    };

                    let response = TxResponse {
                        txid: tx_info.txid.to_string(),
                        version: tx_info.version as i32,
                        locktime: tx_info.locktime,
                        size: tx_info.size,
                        weight,
                        fee: None, // Would require fetching prevouts to calculate
                        vin,
                        vout,
                        status,
                    };
                    Json(response).into_response()
                }
                Ok(Err(e)) => handle_rpc_error(e, "Transaction", &txid).into_response(),
                Err(e) => handle_task_error(e, "get transaction").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid txid: {}: {}", txid, e);
            (StatusCode::BAD_REQUEST, "Invalid txid").into_response()
        }
    }
}

/// GET /api/tx/{txid}/status - Get transaction confirmation status
async fn get_tx_status(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> impl IntoResponse {
    match Txid::from_str(&txid) {
        Ok(tx_id) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || {
                let tx_info = rpc.get_raw_transaction_info(&tx_id, None)?;
                let block_height = if let Some(ref block_hash) = tx_info.blockhash {
                    rpc.get_block_header_info(block_hash)
                        .ok()
                        .map(|info| info.height as u64)
                } else {
                    None
                };
                Ok::<_, bitcoincore_rpc::Error>((tx_info, block_height))
            })
            .await
            {
                Ok(Ok((tx_info, block_height))) => {
                    let status = TxStatus::from_tx_info(&tx_info, block_height);
                    Json(status).into_response()
                }
                Ok(Err(e)) => handle_rpc_error(e, "Transaction", &txid).into_response(),
                Err(e) => handle_task_error(e, "get transaction status").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid txid: {}: {}", txid, e);
            (StatusCode::BAD_REQUEST, "Invalid txid").into_response()
        }
    }
}

/// Compute merkle proof for a transaction at given position in a list of txids
fn compute_merkle_proof(txids: &[Txid], pos: usize) -> Vec<String> {
    use bitcoincore_rpc::bitcoin::hashes::{sha256d, Hash, HashEngine};

    if txids.is_empty() || pos >= txids.len() {
        return vec![];
    }

    // Txid::to_byte_array() returns bytes in internal/consensus order
    // For merkle tree computation in Bitcoin, we use these directly
    let mut hashes: Vec<[u8; 32]> = txids.iter().map(|txid| txid.to_byte_array()).collect();

    let mut proof = Vec::new();
    let mut idx = pos;

    // Build merkle tree level by level
    while hashes.len() > 1 {
        // Get sibling hash for proof
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let sibling = if sibling_idx < hashes.len() {
            hashes[sibling_idx]
        } else {
            // Odd number of elements, duplicate last one
            hashes[idx]
        };

        // Reverse bytes from internal to display order for JSON output
        let mut display_hash = sibling;
        display_hash.reverse();
        proof.push(hex::encode(display_hash));

        // Compute next level - hash pairs together
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() > 1 {
                &chunk[1]
            } else {
                &chunk[0]
            };

            let mut engine = sha256d::Hash::engine();
            engine.input(left);
            engine.input(right);
            let hash = sha256d::Hash::from_engine(engine);
            next_level.push(hash.to_byte_array());
        }
        hashes = next_level;
        idx /= 2;
    }

    proof
}

/// GET /api/tx/{txid}/merkle-proof - Get merkle proof in JSON format
async fn get_tx_merkle_proof(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> impl IntoResponse {
    match Txid::from_str(&txid) {
        Ok(tx_id) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || {
                // Get transaction info to find block hash
                let tx_info = rpc.get_raw_transaction_info(&tx_id, None)?;

                let block_hash = match tx_info.blockhash {
                    Some(hash) => hash,
                    None => {
                        return Err(bitcoincore_rpc::Error::JsonRpc(
                            bitcoincore_rpc::jsonrpc::Error::Rpc(
                                bitcoincore_rpc::jsonrpc::error::RpcError {
                                    code: -5,
                                    message: "Transaction not yet in block".to_string(),
                                    data: None,
                                },
                            ),
                        ))
                    }
                };

                // Get block info for height and txids
                let block_info = rpc.get_block_info(&block_hash)?;

                // Find position of tx in block
                let pos = block_info
                    .tx
                    .iter()
                    .position(|t| *t == tx_id)
                    .ok_or_else(|| {
                        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(
                            bitcoincore_rpc::jsonrpc::error::RpcError {
                                code: -5,
                                message: "Transaction not found in block".to_string(),
                                data: None,
                            },
                        ))
                    })?;

                // Compute merkle proof
                let merkle = compute_merkle_proof(&block_info.tx, pos);

                Ok::<_, bitcoincore_rpc::Error>(MerkleProofResponse {
                    block_height: block_info.height as u64,
                    merkle,
                    pos,
                })
            })
            .await
            {
                Ok(Ok(response)) => Json(response).into_response(),
                Ok(Err(e)) => handle_rpc_error(e, "Transaction", &txid).into_response(),
                Err(e) => handle_task_error(e, "get merkle proof").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid txid: {}: {}", txid, e);
            (StatusCode::BAD_REQUEST, "Invalid txid").into_response()
        }
    }
}

/// GET /api/tx/{txid}/merkleblock-proof - Get merkle inclusion proof
async fn get_tx_merkleblock_proof(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> impl IntoResponse {
    match Txid::from_str(&txid) {
        Ok(tx_id) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || rpc.get_tx_out_proof(&[tx_id], None)).await {
                Ok(Ok(proof)) => {
                    // Return hex-encoded merkle block proof
                    (StatusCode::OK, hex::encode(proof)).into_response()
                }
                Ok(Err(e)) => {
                    // Special case: tx might exist but not be confirmed yet
                    if is_not_found_error(&e) {
                        warn!("Merkle proof unavailable for {}: {}", txid, e);
                        (
                            StatusCode::NOT_FOUND,
                            "Transaction not found or not in a block",
                        )
                            .into_response()
                    } else {
                        warn!("RPC error getting merkle proof for {}: {}", txid, e);
                        (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
                    }
                }
                Err(e) => handle_task_error(e, "get merkle proof").into_response(),
            }
        }
        Err(e) => {
            warn!("Invalid txid: {}: {}", txid, e);
            (StatusCode::BAD_REQUEST, "Invalid txid").into_response()
        }
    }
}

/// POST /api/tx - Broadcast a raw transaction
async fn broadcast_transaction(State(state): State<AppState>, body: String) -> impl IntoResponse {
    // The body should contain the raw transaction in hex format
    let tx_hex = body.trim();

    if tx_hex.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty transaction").into_response();
    }

    // Validate size to prevent DoS
    if tx_hex.len() > MAX_TX_HEX_SIZE {
        return (StatusCode::BAD_REQUEST, "Transaction too large").into_response();
    }

    // Validate it's valid hex
    if hex::decode(tx_hex).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid hex encoding").into_response();
    }

    let rpc = state.rpc.clone();
    let tx_hex_owned = tx_hex.to_string();

    match tokio::task::spawn_blocking(move || rpc.send_raw_transaction(tx_hex_owned)).await {
        Ok(Ok(txid)) => {
            // Return the txid as plain text (esplora format)
            (StatusCode::OK, txid.to_string()).into_response()
        }
        Ok(Err(e)) => {
            // Log detailed error but return generic message to avoid information leakage
            warn!("Failed to broadcast transaction: {}", e);
            (StatusCode::BAD_REQUEST, "Transaction rejected").into_response()
        }
        Err(e) => handle_task_error(e, "broadcast transaction").into_response(),
    }
}

#[derive(Clone)]
struct RouteInfo {
    path: &'static str,
    description: &'static str,
    method: &'static str,
    handler: MethodRouter<AppState, Infallible>,
}

impl RouteInfo {
    fn new(
        path: &'static str,
        description: &'static str,
        handler: MethodRouter<AppState, Infallible>,
    ) -> Self {
        Self {
            path,
            description,
            method: "GET",
            handler,
        }
    }

    fn new_post(
        path: &'static str,
        description: &'static str,
        handler: MethodRouter<AppState, Infallible>,
    ) -> Self {
        Self {
            path,
            description,
            method: "POST",
            handler,
        }
    }
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let mut routes_html = String::with_capacity(1024);
    for route in state.routes.iter() {
        write!(
            routes_html,
            r#"
            <div class="endpoint">
                <div class="path">{} {}</div>
                <p>{}</p>
            </div>
            "#,
            route.method, route.path, route.description
        )
        .expect("writing to string cannot fail");
    }

    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Minipool API Documentation</title>
            <style>
                body {{
                    font-family: system-ui, -apple-system, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 2rem;
                    line-height: 1.6;
                }}
                h1 {{ color: #2563eb; }}
                .endpoint {{
                    background: #f1f5f9;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    margin: 1rem 0;
                }}
                .path {{ font-family: monospace; }}
            </style>
        </head>
        <body>
            <h1>Minipool API Endpoints</h1>
            {}
        </body>
        </html>
        "#,
        routes_html
    ))
}

async fn fallback() -> impl IntoResponse {
    Redirect::temporary("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_compute_merkle_proof_block_100000() {
        // Block 100000 has 4 transactions
        // We test the merkle proof for the coinbase tx (position 0)
        // Expected proof from blockstream.info:
        // {"block_height":100000,"merkle":["fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4","8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49"],"pos":0}

        let txids: Vec<Txid> = vec![
            Txid::from_str("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87")
                .unwrap(),
            Txid::from_str("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4")
                .unwrap(),
            Txid::from_str("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4")
                .unwrap(),
            Txid::from_str("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d")
                .unwrap(),
        ];

        // Test position 0 (coinbase tx)
        let proof = compute_merkle_proof(&txids, 0);
        assert_eq!(proof.len(), 2);
        assert_eq!(
            proof[0],
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"
        );
        assert_eq!(
            proof[1],
            "8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49"
        );
    }

    #[test]
    fn test_compute_merkle_proof_position_1() {
        // Test merkle proof for position 1 (second tx in block 100000)
        let txids: Vec<Txid> = vec![
            Txid::from_str("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87")
                .unwrap(),
            Txid::from_str("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4")
                .unwrap(),
            Txid::from_str("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4")
                .unwrap(),
            Txid::from_str("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d")
                .unwrap(),
        ];

        let proof = compute_merkle_proof(&txids, 1);
        assert_eq!(proof.len(), 2);
        // At position 1, sibling is position 0 (the coinbase)
        assert_eq!(
            proof[0],
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"
        );
    }

    #[test]
    fn test_compute_merkle_proof_single_tx() {
        // Block with single transaction should have empty proof
        let txids: Vec<Txid> = vec![Txid::from_str(
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
        )
        .unwrap()];

        let proof = compute_merkle_proof(&txids, 0);
        assert!(proof.is_empty());
    }

    #[test]
    fn test_compute_merkle_proof_two_txs() {
        // Block with two transactions
        let txids: Vec<Txid> = vec![
            Txid::from_str("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87")
                .unwrap(),
            Txid::from_str("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4")
                .unwrap(),
        ];

        // Position 0 should have tx1 as sibling
        let proof = compute_merkle_proof(&txids, 0);
        assert_eq!(proof.len(), 1);
        assert_eq!(
            proof[0],
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"
        );

        // Position 1 should have tx0 as sibling
        let proof = compute_merkle_proof(&txids, 1);
        assert_eq!(proof.len(), 1);
        assert_eq!(
            proof[0],
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"
        );
    }

    #[test]
    fn test_compute_merkle_proof_empty() {
        let txids: Vec<Txid> = vec![];
        let proof = compute_merkle_proof(&txids, 0);
        assert!(proof.is_empty());
    }

    #[test]
    fn test_compute_merkle_proof_out_of_bounds() {
        let txids: Vec<Txid> = vec![Txid::from_str(
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
        )
        .unwrap()];

        // Position out of bounds should return empty
        let proof = compute_merkle_proof(&txids, 5);
        assert!(proof.is_empty());
    }

    #[test]
    fn test_btc_per_kb_to_sat_per_vb() {
        use bitcoincore_rpc::bitcoin::Amount;

        // 0.00001 BTC/kB = 1000 sat/kB = 1 sat/vB
        assert!(
            (btc_per_kb_to_sat_per_vb(Amount::from_btc(0.00001).unwrap()) - 1.0).abs() < 0.0001
        );

        // 0.0001 BTC/kB = 10000 sat/kB = 10 sat/vB
        assert!(
            (btc_per_kb_to_sat_per_vb(Amount::from_btc(0.0001).unwrap()) - 10.0).abs() < 0.0001
        );

        // 0.00001198 BTC/kB = 1198 sat/kB = 1.198 sat/vB (real example from blockstream)
        assert!(
            (btc_per_kb_to_sat_per_vb(Amount::from_btc(0.00001198).unwrap()) - 1.198).abs()
                < 0.0001
        );

        // 0.0005 BTC/kB = 50000 sat/kB = 50 sat/vB (high fee scenario)
        assert!(
            (btc_per_kb_to_sat_per_vb(Amount::from_btc(0.0005).unwrap()) - 50.0).abs() < 0.0001
        );

        // 0 BTC/kB = 0 sat/vB
        assert_eq!(
            btc_per_kb_to_sat_per_vb(Amount::from_btc(0.0).unwrap()),
            0.0
        );
    }
}
