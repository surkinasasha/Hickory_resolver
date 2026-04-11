use crate::resolver::CachedResolver;
use hickory_server::server::{RequestHandler, ResponseHandler, ResponseInfo, Request};
use hickory_server::authority::MessageResponseBuilder;
use hickory_proto::op::{Message, ResponseCode, Header};
use hickory_proto::rr::{Name, RecordType, Record, RData, rdata::A};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashSet;
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
        let qname = Name::from(query.name().clone());
        let qtype = query.query_type();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let is_offline = *self.resolver.offline_mode.read();
        let q_str = qname.to_string().to_lowercase();

        // --- ШАГ 1: ГЛУБОКИЙ ПОИСК В БАЗЕ (RocksDB FIRST) ---
        if let Some((msg, expires_at)) = self.deep_db_lookup(&qname, qtype) {
            // Если онлайн и запись просрочена - обновляем в фоне
            if !is_offline && expires_at <= now {
                let r = self.resolver.clone();
                let n = qname.clone();
                tokio::spawn(async move { let _ = r.lookup(&n, qtype).await; });
            }
            // Ответ из базы всегда авторитетный (AA)
            return self.finalize_and_send(request, response_handle, msg, true, expires_at, is_offline).await;
        }

        // --- ШАГ 2: NODATA ЛОГИКА (Если домен есть, но тип записи другой) ---
        if self.name_exists_in_db(&qname) {
            let mut empty_msg = Message::new();
            empty_msg.set_response_code(ResponseCode::NoError);
            return self.finalize_and_send(request, response_handle, empty_msg, true, now + 60, is_offline).await;
        }

        // --- ШАГ 3: ОБМАН ПОРТАЛОВ ПРОВЕРКИ (Только в оффлайне) ---
        if is_offline && (
            q_str.contains("detectportal") || 
            q_str.contains("connectivitycheck") || 
            q_str.contains("msftconnecttest") ||
            q_str.contains("captive.apple.com") ||
            q_str.contains("gstatic.com/generate_204")
        ) {
            let mut msg = Message::new();
            if qtype == RecordType::A {
                let fake_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
                msg.add_answer(Record::from_rdata(qname.clone(), 30, RData::A(A::from(fake_ip))));
            } else {
                msg.set_response_code(ResponseCode::NoError);
            }
            return self.finalize_and_send(request, response_handle, msg, true, now + 30, is_offline).await;
        }

        // --- ШАГ 4: ЛОГИКА ОФФЛАЙН РЕЖИМА ---
        if is_offline {
            let mut msg = Message::new();
            // Заглушаем "шумные" типы (IPv6, HTTPS, PTR), чтобы браузер не тормозил
            if qtype == RecordType::AAAA || u16::from(qtype) == 65 || qtype == RecordType::PTR || q_str.contains("arpa") {
                msg.set_response_code(ResponseCode::NoError);
            } else {
                // Для неизвестных A-записей в оффлайне - ServFail (не NXDomain!)
                msg.set_response_code(ResponseCode::ServFail);
            }
            return self.finalize_and_send(request, response_handle, msg, true, now + 30, is_offline).await;
        }

        // --- ШАГ 5: ОНЛАЙН РЕКУРСИЯ (ИНТЕРНЕТ) ---
        let lookup_future = self.resolver.lookup(&qname, qtype);
        match tokio::time::timeout(std::time::Duration::from_millis(2000), lookup_future).await {
            Ok(Ok(Some(data))) => {
                if let Ok(msg) = Message::from_vec(&data) {
                    return self.finalize_and_send(request, response_handle, msg, false, now + 300, is_offline).await;
                }
            }
            _ => {}
        }

        // Если совсем ничего не помогло
        let mut fail = Message::new();
        fail.set_response_code(ResponseCode::ServFail);
        self.finalize_and_send(request, response_handle, fail, false, now, is_offline).await
    }
}

impl BunkerHandler {
    // Проверка существования домена в RocksDB (любого типа)
    fn name_exists_in_db(&self, qname: &Name) -> bool {
        for rtype in [RecordType::A, RecordType::CNAME, RecordType::SOA] {
            let key = format!("{}:{}", qname, rtype).into_bytes();
            if let Ok(Some(_)) = self.resolver.cache.get_stale(&key) {
                return true;
            }
        }
        false
    }

    // Глубокий поиск с поддержкой иерархии меток
    fn deep_db_lookup(&self, qname: &Name, qtype: RecordType) -> Option<(Message, u64)> {
        let mut current_name = qname.clone();
        loop {
            let key = format!("{}:{}", current_name, qtype).into_bytes();
            if let Ok(Some(entry)) = self.resolver.cache.get_stale(&key) {
                if let Ok(msg) = Message::from_vec(&entry.data) {
                    let mut final_msg = Message::new();
                    final_msg.set_response_code(msg.response_code());
                    for r in msg.answers() {
                        let mut new_r = r.clone();
                        if r.name() == &current_name { 
                            new_r.set_name(qname.clone()); 
                        }
                        final_msg.add_answer(new_r);
                    }
                    return Some((final_msg, entry.expires_at));
                }
            }
            if current_name.iter().count() <= 1 { break; }
            current_name = current_name.base_name();
        }
        None
    }

    // Финальная сборка и отправка DNS-пакета
    async fn finalize_and_send<R: ResponseHandler>(
        &self, 
        request: &Request, 
        mut handle: R, 
        msg: Message, 
        auth: bool, 
        expires_at: u64,
        is_offline: bool,
    ) -> ResponseInfo {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut header = Header::response_from_request(request.header());
        
        header.set_authoritative(auth);
        header.set_recursion_available(true);
        header.set_response_code(msg.response_code());
        
        // Установка TTL: 30 секунд в оффлайне, иначе расчетный
        let d_ttl = if is_offline {
            30 
        } else if expires_at <= now {
            10
        } else {
            (expires_at - now).min(3600) as u32
        };
        
        let builder = MessageResponseBuilder::from_message_request(request);
        
        // Списки записей (собираем в Vec, чтобы продлить им жизнь для итератора)
        let answers: Vec<Record> = msg.answers().iter().map(|r| {
            let mut r = r.clone(); r.set_ttl(d_ttl); r
        }).collect();

        let name_servers: Vec<Record> = msg.name_servers().iter().map(|r| {
            let mut r = r.clone(); r.set_ttl(d_ttl); r
        }).collect();

        let additionals: Vec<Record> = msg.additionals().iter().map(|r| {
            let mut r = r.clone(); r.set_ttl(d_ttl); r
        }).collect();

        let response = builder.build(
            header, 
            answers.iter(), 
            name_servers.iter(), 
            &[], 
            additionals.iter()
        );
        
        handle.send_response(response).await.unwrap_or_else(|_| ResponseInfo::from(header))
    }
}
