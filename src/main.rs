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
    routing::get,
    Json, Router,
};
use bitcoincore_rpc::bitcoin::BlockHash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::Parser;
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
        RouteInfo::new(
            "/api/blocks/tip/height",
            "Get the current blockchain tip height.",
            get(get_tip_height),
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
            warn!("Failed to get block count from RPC: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
        Err(e) => {
            warn!("Task failed when getting block count: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
    }
}

async fn get_block_by_height(
    State(state): State<AppState>,
    Path(height): Path<u64>,
) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || rpc.get_block_hash(height)).await {
        Ok(Ok(hash)) => (StatusCode::OK, hash.to_string()).into_response(),
        Ok(Err(e)) => {
            warn!("Failed to get block hash for height {}: {}", height, e);
            (StatusCode::NOT_FOUND, "Block not found").into_response()
        }
        Err(e) => {
            warn!(
                "Task failed when getting block hash for height {}: {}",
                height, e
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
    }
}

fn get_fee_rate_blocking(client: &Client, blocks: u16) -> Result<f64, bitcoincore_rpc::Error> {
    let estimate = client.estimate_smart_fee(blocks, None)?;
    Ok(estimate
        .fee_rate
        .map(|fee_rate| fee_rate.to_btc())
        .unwrap_or_else(|| {
            warn!(
                "No fee rate estimate available for {} blocks, using default",
                blocks
            );
            0.0001
        }))
}

async fn get_fee_estimates(State(state): State<AppState>) -> impl IntoResponse {
    let rpc = state.rpc.clone();
    match tokio::task::spawn_blocking(move || {
        CONFIRMATION_TARGETS
            .iter()
            .map(|&blocks| Ok((blocks.to_string(), get_fee_rate_blocking(&rpc, blocks)?)))
            .collect::<Result<BTreeMap<_, _>, bitcoincore_rpc::Error>>()
    })
    .await
    {
        Ok(Ok(estimates)) => Json(estimates).into_response(),
        Ok(Err(e)) => {
            warn!("Failed to get fee estimates: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
        Err(e) => {
            warn!("Task failed when getting fee estimates: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
        }
    }
}

async fn get_block_raw(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match BlockHash::from_str(&hash) {
        Ok(block_hash) => {
            let rpc = state.rpc.clone();
            match tokio::task::spawn_blocking(move || rpc.get_block_hex(&block_hash)).await {
                Ok(Ok(block_hex)) => (StatusCode::OK, block_hex).into_response(),
                Ok(Err(e)) => {
                    warn!("Failed to get raw block for hash {}: {}", hash, e);
                    (StatusCode::NOT_FOUND, "Block not found").into_response()
                }
                Err(e) => {
                    warn!(
                        "Task failed when getting raw block for hash {}: {}",
                        hash, e
                    );
                    (StatusCode::INTERNAL_SERVER_ERROR, "RPC error").into_response()
                }
            }
        }
        Err(e) => {
            warn!("Invalid block hash provided {}: {}", hash, e);
            (StatusCode::BAD_REQUEST, "Invalid block hash").into_response()
        }
    }
}

#[derive(Clone)]
struct RouteInfo {
    path: &'static str,
    description: &'static str,
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
                <div class="path">GET {}</div>
                <p>{}</p>
            </div>
            "#,
            route.path, route.description
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
