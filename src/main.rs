mod storage;
mod resolver;
mod handler;
mod api;

use hickory_server::ServerFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashSet;
use tokio::net::{TcpListener, UdpSocket};
use axum::routing::post;
use crate::resolver::CachedResolver;
use crate::handler::BunkerHandler;
use crate::api::{ApiState, set_mode, freeze_zone, stats, add_record};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let resolver = Arc::new(CachedResolver::new("./dns_cache").await.unwrap());
    let rocksdb_zones = Arc::new(RwLock::new(HashSet::new()));
    let zones_insecure = Arc::new(RwLock::new(HashSet::new()));

    let handler = BunkerHandler {
        resolver: resolver.clone(),
        rocksdb_zones: rocksdb_zones.clone(),
        zones_insecure: zones_insecure.clone(),
    };

    let handler_arc = Arc::new(handler.clone());
    let mut server = ServerFuture::new(handler);
    
    // Ставим порт 1053 (или 53, если есть права)
    let socket = UdpSocket::bind("0.0.0.0:1053").await.expect("Bind failed");
    server.register_socket(socket);

    tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });

    let api_state = Arc::new(ApiState { resolver, handler: handler_arc });
    let app = axum::Router::new()
        .route("/mode", post(set_mode))
        .route("/freeze", post(freeze_zone))
        .route("/stats", post(stats))
        .route("/add_record", post(add_record)) // Новый роут
        .with_state(api_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("API on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
