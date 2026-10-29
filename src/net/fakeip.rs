use crate::dataplane::router::RouteMatcher;
use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;

const FAKE_IP_START: u32 = 0xc6120001; // 198.18.0.1
const FAKE_IP_END: u32 = 0xc613fffe;   // 198.19.255.254

#[derive(Debug)]
pub struct FakeIpState {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
    current_ip: u32,
}

#[derive(Debug, Clone)]
pub struct FakeIpPool {
    state: Arc<RwLock<FakeIpState>>,
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIpPool {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(FakeIpState {
                domain_to_ip: HashMap::new(),
                ip_to_domain: HashMap::new(),
                current_ip: FAKE_IP_START,
            })),
        }
    }

    pub async fn allocate_or_get(&self, domain: &str) -> Ipv4Addr {
        let clean = domain.trim().trim_end_matches('.').to_lowercase();
        let mut s = self.state.write().await;

        if let Some(&ip) = s.domain_to_ip.get(&clean) {
            return ip;
        }

        let ip_num = s.current_ip;
        if s.current_ip >= FAKE_IP_END {
            s.current_ip = FAKE_IP_START;
        } else {
            s.current_ip += 1;
        }

        let ip = Ipv4Addr::from(ip_num);
        if let Some(old_domain) = s.ip_to_domain.insert(ip, clean.clone()) {
            s.domain_to_ip.remove(&old_domain);
        }
        s.domain_to_ip.insert(clean, ip);
        ip
    }

    pub async fn lookup_domain(&self, ip: Ipv4Addr) -> Option<String> {
        let s = self.state.read().await;
        s.ip_to_domain.get(&ip).cloned()
    }

    pub fn is_fake_ip(ip: Ipv4Addr) -> bool {
        let num: u32 = ip.into();
        (FAKE_IP_START..=FAKE_IP_END).contains(&num)
    }
}

pub struct DnsServer {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    router: Arc<RouteMatcher>,
    fake_pool: FakeIpPool,
}

impl DnsServer {
    pub fn new(
        listen_addr: SocketAddr,
        upstream_addr: SocketAddr,
        router: Arc<RouteMatcher>,
        fake_pool: FakeIpPool,
    ) -> Self {
        Self {
            listen_addr,
            upstream_addr,
            router,
            fake_pool,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let udp_socket = Arc::new(
            UdpSocket::bind(self.listen_addr)
                .await
                .with_context(|| format!("Failed to bind DNS UDP server on {}", self.listen_addr))?,
        );

        let tcp_listener = match TcpListener::bind(self.listen_addr).await {
            Ok(l) => Some(l),
            Err(e) => {
                tracing::warn!("Failed to bind DNS TCP server on {}: {:?}. UDP only active.", self.listen_addr, e);
                None
            }
        };

        tracing::info!(
            "DNS server listening on {} (UDP/TCP, upstream: {})",
            self.listen_addr,
            self.upstream_addr
        );

        // Task: Handle UDP queries
        let udp_sock_clone = Arc::clone(&udp_socket);
        let router_clone = Arc::clone(&self.router);
        let fake_pool_clone = self.fake_pool.clone();
        let upstream = self.upstream_addr;

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (len, client_addr) = match udp_sock_clone.recv_from(&mut buf).await {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::warn!("DNS UDP recv error: {:?}", e);
                        continue;
                    }
                };

                let req_bytes = buf[..len].to_vec();
                let sock = Arc::clone(&udp_sock_clone);
                let router = Arc::clone(&router_clone);
                let fake_pool = fake_pool_clone.clone();

                tokio::spawn(async move {
                    match Self::handle_query(&req_bytes, router, fake_pool, upstream).await {
                        Ok(resp_bytes) => {
                            let _ = sock.send_to(&resp_bytes, client_addr).await;
                        }
                        Err(e) => {
                            tracing::debug!("DNS UDP query error from {}: {:?}", client_addr, e);
                        }
                    }
                });
            }
        });

        // Task: Handle TCP queries
        if let Some(listener) = tcp_listener {
            let router = Arc::clone(&self.router);
            let fake_pool = self.fake_pool.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _client_addr) = match listener.accept().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("DNS TCP accept error: {:?}", e);
                            continue;
                        }
                    };

                    let router = Arc::clone(&router);
                    let fake_pool = fake_pool.clone();

                    tokio::spawn(async move {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let req_len = u16::from_be_bytes(len_buf) as usize;
                        let mut req_buf = vec![0u8; req_len];
                        if stream.read_exact(&mut req_buf).await.is_err() {
                            return;
                        }

                        if let Ok(resp_bytes) = Self::handle_query(&req_buf, router, fake_pool, upstream).await {
                            let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                            let _ = stream.write_all(&resp_len).await;
                            let _ = stream.write_all(&resp_bytes).await;
                        }
                    });
                }
            });
        }

        Ok(())
    }

    pub async fn handle_query(
        req_bytes: &[u8],
        router: Arc<RouteMatcher>,
        fake_pool: FakeIpPool,
        upstream: SocketAddr,
    ) -> Result<Vec<u8>> {
        let mut decoder = BinDecoder::new(req_bytes);
        let request = Message::read(&mut decoder)
            .context("Failed to decode DNS request")?;

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(request.op_code());
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(true);
        response.set_authoritative(true);

        // Mirror EDNS0 if present in request (essential for systemd-resolved)
        if let Some(edns) = request.extensions().as_ref() {
            let mut resp_edns = edns.clone();
            resp_edns.set_dnssec_ok(false);
            response.set_edns(resp_edns);
        }

        if let Some(query) = request.queries().first() {
            let name_str = query.name().to_utf8();
            let clean_domain = name_str.trim_end_matches('.');
            let is_corp = router.matches_domain(clean_domain);

            response.add_query(query.clone());

            if is_corp {
                match query.query_type() {
                    RecordType::A => {
                        let fake_ip = fake_pool.allocate_or_get(clean_domain).await;
                        let mut record = Record::from_rdata(
                            query.name().clone(),
                            5, // 5 seconds TTL as per spec
                            RData::A(A(fake_ip)),
                        );
                        record.set_record_type(RecordType::A);
                        response.add_answer(record);
                        response.set_response_code(ResponseCode::NoError);

                        let mut out_bytes = Vec::with_capacity(512);
                        let mut encoder = BinEncoder::new(&mut out_bytes);
                        response.emit(&mut encoder)?;
                        tracing::debug!("DNS resolved {} -> {} (Fake-IP)", clean_domain, fake_ip);
                        return Ok(out_bytes);
                    }
                    _ => {
                        // Return empty NOERROR (NODATA) for corporate domains for all other query types
                        // (AAAA, HTTPS type 65, TXT, etc.). NEVER forward corporate domains upstream!
                        response.set_response_code(ResponseCode::NoError);
                        let mut out_bytes = Vec::with_capacity(512);
                        let mut encoder = BinEncoder::new(&mut out_bytes);
                        response.emit(&mut encoder)?;
                        tracing::debug!(
                            "DNS resolved {} -> NODATA ({:?})",
                            clean_domain,
                            query.query_type()
                        );
                        return Ok(out_bytes);
                    }
                }
            }
        }

        // Forward non-corporate query to upstream resolver
        let up_sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to bind UDP socket for upstream DNS: {:?}", e);
                response.set_response_code(ResponseCode::ServFail);
                let mut out_bytes = Vec::with_capacity(512);
                let mut encoder = BinEncoder::new(&mut out_bytes);
                response.emit(&mut encoder)?;
                return Ok(out_bytes);
            }
        };

        if let Err(e) = up_sock.send_to(req_bytes, upstream).await {
            tracing::warn!("Failed to send to upstream DNS {}: {:?}", upstream, e);
            response.set_response_code(ResponseCode::ServFail);
            let mut out_bytes = Vec::with_capacity(512);
            let mut encoder = BinEncoder::new(&mut out_bytes);
            response.emit(&mut encoder)?;
            return Ok(out_bytes);
        }

        let mut up_buf = [0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            up_sock.recv(&mut up_buf),
        )
        .await
        {
            Ok(Ok(n)) => Ok(up_buf[..n].to_vec()),
            _ => {
                response.set_response_code(ResponseCode::ServFail);
                let mut out_bytes = Vec::with_capacity(512);
                let mut encoder = BinEncoder::new(&mut out_bytes);
                response.emit(&mut encoder)?;
                Ok(out_bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fake_ip_allocation() {
        let pool = FakeIpPool::new();

        let ip1 = pool.allocate_or_get("git.example.corp").await;
        assert_eq!(ip1, Ipv4Addr::new(198, 18, 0, 1));
        assert!(FakeIpPool::is_fake_ip(ip1));

        let ip2 = pool.allocate_or_get("example.corp").await;
        assert_eq!(ip2, Ipv4Addr::new(198, 18, 0, 2));

        // Re-allocation should return identical IP
        let ip1_again = pool.allocate_or_get("git.example.corp").await;
        assert_eq!(ip1, ip1_again);

        // Reverse lookup
        let domain = pool.lookup_domain(ip1).await;
        assert_eq!(domain.as_deref(), Some("git.example.corp"));

        let domain2 = pool.lookup_domain(ip2).await;
        assert_eq!(domain2.as_deref(), Some("example.corp"));

        let unknown = pool.lookup_domain(Ipv4Addr::new(198, 18, 99, 99)).await;
        assert_eq!(unknown, None);
    }

    #[tokio::test]
    async fn test_fake_ip_wrap_around_evicts_old_domain() {
        let pool = FakeIpPool::new();
        let ip_first = pool.allocate_or_get("old.example.corp").await;
        assert_eq!(ip_first, Ipv4Addr::from(FAKE_IP_START));

        // Force wrap-around back to FAKE_IP_START
        {
            let mut s = pool.state.write().await;
            s.current_ip = FAKE_IP_START;
        }

        let ip_reused = pool.allocate_or_get("new.example.corp").await;
        assert_eq!(ip_reused, ip_first);
        assert_eq!(
            pool.lookup_domain(ip_reused).await.as_deref(),
            Some("new.example.corp")
        );

        // Allocating old.example.corp again must allocate a fresh IP, not the overwritten one
        let ip_old_reallocated = pool.allocate_or_get("old.example.corp").await;
        assert_ne!(ip_old_reallocated, ip_reused);
    }

    #[tokio::test]
    async fn test_dns_server_corporate_queries() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let pool = FakeIpPool::new();
        let mut router = RouteMatcher::new();
        router.fqdn_includes.push(crate::dataplane::router::DomainPattern::parse("*.example.corp"));
        let router = Arc::new(router);
        let dummy_upstream = "127.0.0.1:53".parse().unwrap();

        // 1. Test A record query for consul.internal.example.corp
        let mut msg_a = Message::new();
        msg_a.set_id(1234);
        msg_a.add_query(Query::query(
            Name::from_str("consul.internal.example.corp.").unwrap(),
            RecordType::A,
        ));
        let mut req_bytes_a = Vec::new();
        let mut encoder = BinEncoder::new(&mut req_bytes_a);
        msg_a.emit(&mut encoder).unwrap();

        let resp_bytes_a = DnsServer::handle_query(&req_bytes_a, Arc::clone(&router), pool.clone(), dummy_upstream)
            .await
            .expect("handle_query failed");
        let resp_a = Message::from_vec(&resp_bytes_a).expect("parse response");
        assert_eq!(resp_a.response_code(), ResponseCode::NoError);
        assert_eq!(resp_a.answers().len(), 1);
        if let Some(RData::A(ip)) = resp_a.answers()[0].data() {
            assert!(FakeIpPool::is_fake_ip(ip.0));
        } else {
            panic!("Expected A record in answer");
        }

        // 2. Test AAAA record query for consul.internal.example.corp (NODATA)
        let mut msg_aaaa = Message::new();
        msg_aaaa.set_id(5678);
        msg_aaaa.add_query(Query::query(
            Name::from_str("consul.internal.example.corp.").unwrap(),
            RecordType::AAAA,
        ));
        let mut req_bytes_aaaa = Vec::new();
        let mut encoder = BinEncoder::new(&mut req_bytes_aaaa);
        msg_aaaa.emit(&mut encoder).unwrap();

        let resp_bytes_aaaa = DnsServer::handle_query(&req_bytes_aaaa, Arc::clone(&router), pool.clone(), dummy_upstream)
            .await
            .expect("handle_query failed");
        let resp_aaaa = Message::from_vec(&resp_bytes_aaaa).expect("parse response");
        assert_eq!(resp_aaaa.response_code(), ResponseCode::NoError);
        assert_eq!(resp_aaaa.answers().len(), 0);

        // 3. Test HTTPS (type 65) record query (NODATA, must NOT forward upstream)
        let mut msg_https = Message::new();
        msg_https.set_id(9999);
        msg_https.add_query(Query::query(
            Name::from_str("consul.internal.example.corp.").unwrap(),
            RecordType::HTTPS,
        ));
        let mut req_bytes_https = Vec::new();
        let mut encoder = BinEncoder::new(&mut req_bytes_https);
        msg_https.emit(&mut encoder).unwrap();

        let resp_bytes_https = DnsServer::handle_query(&req_bytes_https, Arc::clone(&router), pool.clone(), dummy_upstream)
            .await
            .expect("handle_query failed");
        let resp_https = Message::from_vec(&resp_bytes_https).expect("parse response");
        assert_eq!(resp_https.response_code(), ResponseCode::NoError);
        assert_eq!(resp_https.answers().len(), 0);
    }
}
