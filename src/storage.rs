use rocksdb::{DB, Options};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CacheEntry {
    pub data: Vec<u8>,
    pub expires_at: u64,
    pub original_ttl: u32,
}

pub struct DnsCache {
    pub db: Arc<DB>,
}

impl DnsCache {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn put(&self, key: &[u8], entry: &CacheEntry) -> anyhow::Result<()> {
        let bin = bincode::serialize(entry)?;
        self.db.put(key, bin)?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> anyhow::Result<Option<CacheEntry>> {
        if let Some(bin) = self.db.get(key)? {
            let entry: CacheEntry = bincode::deserialize(&bin)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn get_stale(&self, key: &[u8]) -> anyhow::Result<Option<CacheEntry>> {
        self.get(key)
    }

    pub fn get_estimated_key_count(&self) -> u64 {
        self.db.property_value("rocksdb.estimate-num-keys")
            .unwrap_or(Some("0".to_string()))
            .unwrap_or("0".to_string())
            .parse::<u64>()
            .unwrap_or(0)
    }
}
