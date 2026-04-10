use crate::resolver::CachedResolver;
use crate::handler::BunkerHandler;
use axum::{Json, extract::State};
use serde_json::{json, Value};
use std::sync::Arc;
use std::str::FromStr;
use hickory_proto::rr::{Record, RData, Name};
use hickory_proto::rr::rdata::A; 
use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::{BinEncoder, BinEncodable};

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

pub async fn add_record(State(state): State<Arc<ApiState>>, Json(payload): Json<Value>) -> Json<Value> {
    let name_str = payload["name"].as_str().unwrap_or("");
    let ip_str = payload["ip"].as_str().unwrap_or("");

    if name_str.is_empty() || ip_str.is_empty() {
        return Json(json!({"error": "name and ip required"}));
    }

    let fqdn = if name_str.ends_with('.') { name_str.to_string() } else { format!("{}.", name_str) };
    let name = match Name::from_str(&fqdn) {
        Ok(n) => n,
        Err(_) => return Json(json!({"error": "invalid domain name"})),
    };

    let ip = match std::net::Ipv4Addr::from_str(ip_str) {
        Ok(addr) => addr,
        Err(_) => return Json(json!({"error": "invalid ipv4 address"})),
    };

    let mut msg = Message::new();
    msg.set_message_type(MessageType::Response);
    msg.set_authoritative(true);
    
    msg.add_answer(Record::from_rdata(name.clone(), 3600, RData::A(A::from(ip))));

    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    if let Err(_) = msg.emit(&mut encoder) {
        return Json(json!({"error": "serialization failed"}));
    }

    let entry = crate::storage::CacheEntry {
        data: bytes,
        expires_at: u64::MAX / 2, 
        original_ttl: 3600,
    };

    let key = format!("{}:A", name).into_bytes();
    state.resolver.cache.put(&key, &entry).unwrap();
    state.handler.rocksdb_zones.write().insert(name_str.to_string());

    Json(json!({"status": "success", "domain": name_str, "ip": ip_str}))
}
