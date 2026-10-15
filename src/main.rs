mod asn;
mod flow;
mod pipeline;
mod prometheus;
mod sse;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use clap::Parser;
use rust_embed::Embed;
use tracing_subscriber::EnvFilter;

#[derive(Embed)]
#[folder = "frontend/dist/"]
struct Assets;

pub struct AppState {
    pub asn_db: Arc<ArcSwap<asn::AsnDb>>,
    pub windows: Arc<pipeline::WindowManager>,
    pub skip_asns: Vec<u32>,
}

#[derive(Parser)]
#[command(
    name = "netra",
    about = "Network flow analyzer with ASN mapping and live dashboard"
)]
struct Args {
    /// UDP port to listen for NetFlow/IPFIX/sFlow packets
    #[arg(short = 'f', long, default_value_t = 2055)]
    flow_port: u16,

    /// TCP port for the HTTP dashboard and SSE API
    #[arg(short = 'p', long, default_value_t = 1337)]
    http_port: u16,

    /// Path to the ASN database file.
    /// Default: asndb.netra in the project directory, or next to the binary.
    #[arg(short = 'd', long, default_value = None)]
    db_path: Option<PathBuf>,

    /// Comma-separated list of ASNs to exclude from charts and lists
    #[arg(long, value_delimiter = ',')]
    skip_asns: Vec<u32>,
}

/// Directory for `asndb.netra` when `--db-path` is not set.
///
/// A checkout stores it at the project root (the directory that contains
/// `Cargo.toml`), so a process started with cwd `/` does not write the
/// database there. An installed binary with no project tree nearby keeps
/// the file next to the executable.
fn default_db_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(db_dir_from_exe)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn db_dir_from_exe(exe: &std::path::Path) -> Option<PathBuf> {
    let start = exe.parent()?;
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("Cargo.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    Some(start.to_path_buf())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    tracing::info!("netra starting up");

    // --- ASN database ---
    let db_path = args
        .db_path
        .unwrap_or_else(|| default_db_dir().join("asndb.netra"));

    let asn_db_arc = match asn::init(&db_path).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("Failed to initialize ASN database: {e}");
            std::process::exit(1);
        }
    };
    let asn_swap = Arc::new(ArcSwap::from(asn_db_arc));

    // --- Flow processing pipeline ---
    let windows = Arc::new(pipeline::WindowManager::new());

    // --- UDP receive mode detection ---
    flow::xdp::log_xdp_status();

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let flow_port = args.flow_port;

    let _listeners = if let Some(ref iface) = flow::xdp::xdp_interface() {
        if flow::xdp::probe_af_xdp() {
            match flow::xdp::try_spawn_xdp(iface, flow_port, asn_swap.clone(), windows.clone()) {
                Ok(handles) => {
                    tracing::info!(
                        "UDP receive: AF_XDP zero-copy on {iface} ({} queues)",
                        handles.len()
                    );
                    handles
                }
                Err(e) => {
                    tracing::warn!("AF_XDP setup failed: {e}");
                    let mode = flow::listener::detect_mode();
                    tracing::info!(
                        "UDP receive: falling back to {mode} on port {flow_port} ({cores} threads)"
                    );
                    flow::listener::spawn_listeners(
                        cores,
                        mode,
                        flow_port,
                        asn_swap.clone(),
                        windows.clone(),
                    )
                }
            }
        } else {
            let mode = flow::listener::detect_mode();
            tracing::info!("UDP receive: {mode} on port {flow_port} ({cores} threads)");
            flow::listener::spawn_listeners(
                cores,
                mode,
                flow_port,
                asn_swap.clone(),
                windows.clone(),
            )
        }
    } else {
        let mode = flow::listener::detect_mode();
        tracing::info!("UDP receive: {mode} on port {flow_port} ({cores} threads)");
        flow::listener::spawn_listeners(cores, mode, flow_port, asn_swap.clone(), windows.clone())
    };

    tokio::spawn(pipeline::rotation_loop(windows.clone()));
    tokio::spawn(pipeline::snapshot_loop(windows.clone()));
    tokio::spawn(asn::refresh_loop(db_path, asn_swap.clone()));

    if !args.skip_asns.is_empty() {
        tracing::info!("Excluding ASNs from charts: {:?}", args.skip_asns);
    }

    let state = Arc::new(AppState {
        asn_db: asn_swap,
        windows,
        skip_asns: args.skip_asns,
    });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/events", get(sse::events_handler))
        .route("/metrics", get(prometheus::metrics_handler))
        .fallback(static_handler)
        .with_state(state);

    let http_addr = format!("0.0.0.0:{}", args.http_port);
    let listener = tokio::net::TcpListener::bind(&http_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {http_addr}: {e}"));

    tracing::info!("Listening on http://{http_addr}");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("Server error");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn static_handler(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .header(header::PRAGMA, "no-cache")
            .header(header::EXPIRES, "0")
            .body(axum::body::Body::from(file.data.to_vec()))
            .unwrap();
    }

    match Assets::get("index.html") {
        Some(file) => Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .header(header::PRAGMA, "no-cache")
            .header(header::EXPIRES, "0")
            .body(axum::body::Body::from(file.data.to_vec()))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("Not Found"))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::db_dir_from_exe;
    use std::fs;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netra-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn db_dir_is_cargo_project_root() {
        let root = scratch("proj");
        let bin_dir = root.join("target/release");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(root.join("Cargo.toml"), b"[package]\nname = \"netra\"\n").unwrap();

        let got = db_dir_from_exe(&bin_dir.join("netra")).unwrap();
        assert_eq!(got, root);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn db_dir_falls_back_to_exe_directory() {
        let root = scratch("installed");
        let got = db_dir_from_exe(&root.join("netra")).unwrap();
        assert_eq!(got, root);
        fs::remove_dir_all(&root).unwrap();
    }
}
