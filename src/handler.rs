use crate::resolver::CachedResolver;
use hickory_server::server::{RequestHandler, ResponseHandler, ResponseInfo, Request};
use hickory_server::authority::MessageResponseBuilder;
use hickory_proto::op::{Message, MessageType, ResponseCode, Header};
use hickory_proto::rr::{Name, LowerName};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use async_trait::async_trait;

#[derive(Clone)]
pub struct BunkerHandler {
    pub resolver: Arc<CachedResolver>,
    pub rocksdb_zones: Arc<RwLock<HashSet<String>>>,
    pub zones_insecure: Arc<RwLock<HashSet<String>>>,
}

#[async_trait]
impl RequestHandler for BunkerHandler {
    async fn handle_request<R: ResponseHandler>(&self, request: &Request, response_handle: R) -> ResponseInfo {
        let query = request.request_info().query;
        let qname = query.name();
        let qtype = query.query_type();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let is_offline = *self.resolver.offline_mode.read();

        let zone_found = {
            let zones = self.rocksdb_zones.read();
            zones.iter()
                .filter_map(|z| Name::from_str(&format!("{}.", z)).ok().map(|n| (z.clone(), LowerName::from(n))))
                .find(|(_, fqdn)| qname.zone_of(fqdn))
                .map(|(name, _)| name)
        };

        if let Some(_) = zone_found {
            let key = format!("{}:{}", qname, qtype).into_bytes();
            if let Ok(Some(entry)) = self.resolver.cache.get_stale(&key) {
                if let Ok(mut msg) = Message::from_vec(&entry.data) {
                    msg.set_authoritative(true);
                    let rem_ttl = entry.expires_at.saturating_sub(now) as u32;
                    let d_ttl = if rem_ttl == 0 { 30 } else { rem_ttl };
                    for r in msg.answers_mut() { r.set_ttl(d_ttl); }
                    return self.send_msg(request, response_handle, msg).await;
                }
            }
        }

        let lookup_name = Name::from(qname.clone());
        match self.resolver.lookup(&lookup_name, qtype).await {
            Ok(Some(data)) => {
                if let Ok(mut msg) = Message::from_vec(&data) {
                    msg.set_authoritative(is_offline); 
                    let key = format!("{}:{}", qname, qtype).into_bytes();
                    if let Ok(Some(entry)) = self.resolver.cache.get_stale(&key) {
                        let rem_ttl = entry.expires_at.saturating_sub(now) as u32;
                        let d_ttl = if rem_ttl == 0 { 30 } else { rem_ttl };
                        for r in msg.answers_mut() { r.set_ttl(d_ttl); }
                    }
                    return self.send_msg(request, response_handle, msg).await;
                }
            }
            _ => {
                let mut res = Message::new();
                res.set_response_code(ResponseCode::ServFail);
                return self.send_msg(request, response_handle, res).await;
            }
        }
        ResponseInfo::from(Header::new())
    }
}

impl BunkerHandler {
    async fn send_msg<R: ResponseHandler>(&self, request: &Request, mut handle: R, mut message: Message) -> ResponseInfo {
        message.set_id(request.id());
        message.set_message_type(MessageType::Response);
        message.set_recursion_available(true);
        message.set_recursion_desired(request.recursion_desired());

        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.build(*message.header(), message.answers().iter(), message.name_servers().iter(), &[], message.additionals().iter());
        handle.send_response(response).await.unwrap_or_else(|_| ResponseInfo::from(Header::new()))
    }
}
