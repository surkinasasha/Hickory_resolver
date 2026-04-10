use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_proto::rr::{RecordType, Name};
use hickory_proto::op::{Message, Query, MessageType};
use hickory_proto::serialize::binary::{BinEncoder, BinEncodable};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use anyhow::Result;

use crate::storage::{DnsCache, CacheEntry};

pub struct CachedResolver {
    pub cache: Arc<DnsCache>,
    inner: TokioAsyncResolver,
    pub offline_mode: Arc<RwLock<bool>>,
}

impl CachedResolver {
    pub async fn new(cache_path: &str) -> Result<Self> {
        let cache = Arc::new(DnsCache::new(cache_path)?);

        let mut opts = ResolverOpts::default();
        opts.validate = true; // DNSSEC Валидация включена
        
        let config = ResolverConfig::google(); // Рекурсия через Google с DNSSEC
        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self {
            cache,
            inner: resolver,
            offline_mode: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn lookup(&self, name: &Name, qtype: RecordType) -> Result<Option<Vec<u8>>> {
        let key = format!("{}:{}", name, qtype).into_bytes();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let offline = *self.offline_mode.read();

        // 1. Сначала база
        if let Ok(Some(entry)) = self.cache.get_stale(&key) {
            let is_stale = entry.expires_at <= now;
            let ttl_left = entry.expires_at.saturating_sub(now);

            if !offline && (is_stale || ttl_left < (entry.original_ttl as u64 / 3).max(30)) {
                let resolver = self.inner.clone();
                let cache = self.cache.clone();
                let n = name.clone();
                let k = key.clone();
                let ottl = entry.original_ttl;
                tokio::spawn(async move {
                    if let Ok(Some(data)) = Self::do_recursive(&resolver, &n, qtype).await {
                        let _ = cache.put(&k, &CacheEntry {
                            data,
                            expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + ottl as u64,
                            original_ttl: ottl,
                        });
                    }
                });
            }
            return Ok(Some(entry.data));
        }

        // 2. Интернет (если не Offline)
        if !offline {
            if let Ok(Some(wire_data)) = Self::do_recursive(&self.inner, name, qtype).await {
                let ttl = if let Ok(m) = Message::from_vec(&wire_data) {
                    m.answers().first().map(|r| r.ttl()).unwrap_or(300)
                } else { 300 };

                self.cache.put(&key, &CacheEntry {
                    data: wire_data.clone(),
                    expires_at: now + ttl as u64,
                    original_ttl: ttl,
                })?;
                return Ok(Some(wire_data));
            }
        }
        Ok(None)
    }

    async fn do_recursive(resolver: &TokioAsyncResolver, name: &Name, qtype: RecordType) -> Result<Option<Vec<u8>>> {
        match resolver.lookup(name.clone(), qtype).await {
            Ok(lookup_result) => {
                let mut msg = Message::new();
                msg.set_message_type(MessageType::Response);
                let mut q = Query::new();
                q.set_name(name.clone());
                q.set_query_type(qtype);
                msg.add_query(q);
                for rec in lookup_result.record_iter() {
                    msg.add_answer(rec.clone());
                }
                let mut bytes = Vec::new();
                let mut enc = BinEncoder::new(&mut bytes);
                msg.emit(&mut enc)?;
                Ok(Some(bytes))
            }
            Err(e) => {
                tracing::error!("DNSSEC/Network error for {}: {}", name, e);
                Ok(None)
            }
        }
    }

    pub fn set_offline(&self, offline: bool) {
        *self.offline_mode.write() = offline;
    }
}
