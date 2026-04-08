use crate::resolver::CachedResolver;
use crate::handler::BunkerHandler;
use axum::{Json, extract::State};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct ApiState {
    pub resolver: Arc<CachedResolver>,
    pub handler: Arc<BunkerHandler>,
}

pub async fn set_mode(State(state): State<Arc<ApiState>>, Json(payload): Json<Value>) -> Json<Value> {
    let offline = payload["offline"].as_bool().unwrap_or(false);
    state.resolver.set_offline(offline);
    Json(json!({"offline": offline}))
}

pub async fn freeze_zone(State(state): State<Arc<ApiState>>, Json(payload): Json<Value>) -> Json<Value> {
    let zone = payload["zone"].as_str().unwrap_or("").to_string();
    if !zone.is_empty() {
        state.handler.rocksdb_zones.write().insert(zone.clone());
    }
    Json(json!({"status": "frozen", "zone": zone}))
}

pub async fn stats(State(state): State<Arc<ApiState>>) -> Json<Value> {
    let zones: Vec<String> = state.handler.rocksdb_zones.read().iter().cloned().collect();
    let offline = *state.resolver.offline_mode.read();
    let count = state.resolver.cache.get_estimated_key_count();
    Json(json!({
        "offline_mode": offline,
        "rocksdb_zones": zones,
        "cache_entries_count": count
    }))
}
