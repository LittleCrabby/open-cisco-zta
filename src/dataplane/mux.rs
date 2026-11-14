use crate::crypto::{create_ssl_connector, TlsConfig};
use crate::plugins::{DefaultAcidexProvider, FlowInfo, FlowMetadataProvider};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Version};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::task::AbortHandle;

pub use crate::dataplane::masque::*;
pub use crate::dataplane::relay::*;
pub use crate::dataplane::stream::*;

/// Maximum time to establish a new TCP + mTLS + HTTP/2 connection to the Cisco ZPC proxy.
const H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time to wait for `h2::client::SendRequest::ready()` on a cached connection.
const H2_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for an HTTP/2 `CONNECT` or `CONNECT-UDP` response header from the proxy
/// on the final attempt.
const H2_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Fast per-stream timeout for initial `HTTP/2 CONNECT` / `CONNECT-UDP` attempts so a stream
/// routed to a stalled on-premises ZTA Connector (which takes ~7.15s to return `504 Gateway Timeout`)
/// is cancelled (`RST_STREAM`) and retried on a fresh stream in 2.5s without tearing down the
/// shared HTTP/2 connection.
const H2_FAST_CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);

/// Maximum number of `HTTP/2 CONNECT` / `CONNECT-UDP` attempts across transient connection errors
/// or upstream ZTA connector gateway errors (`502` / `503` / `504`).
const H2_MAX_CONNECT_ATTEMPTS: usize = 3;

/// Returns `true` if `status` indicates a transient upstream ZTA Connector / gateway failure
/// (`502 Bad Gateway`, `503 Service Unavailable`, `504 Gateway Timeout`) that should be retried
/// on a new HTTP/2 stream.
fn is_retryable_gateway_status(status: http::StatusCode) -> bool {
    matches!(
        status,
        http::StatusCode::BAD_GATEWAY
            | http::StatusCode::SERVICE_UNAVAILABLE
            | http::StatusCode::GATEWAY_TIMEOUT
    )
}

/// Interval between HTTP/2 `PING` keepalive frames on the multiplex connection.
const H2_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time to wait for an HTTP/2 `PONG` response before declaring the connection dead.
const H2_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum wall-clock age since the last verified HTTP/2 `PONG` (or connection creation).
/// Because `CLOCK_MONOTONIC` (`tokio::time::Instant`) pauses while the OS is suspended (`s2idle`/`S3`),
/// checking `SystemTime` age immediately detects connections that went stale across system sleep.
const H2_MAX_PONG_AGE: Duration = Duration::from_secs(75);

struct CachedH2Client {
    conn_id: u64,
    client: h2::client::SendRequest<Bytes>,
    local_ip: Option<IpAddr>,
    peer_addr: Option<SocketAddr>,
    last_pong_wall: Arc<std::sync::Mutex<SystemTime>>,
    driver_abort: AbortHandle,
    ping_abort: Option<AbortHandle>,
}

impl CachedH2Client {
    /// Performs a zero-cost (non-network) viability check on the cached HTTP/2 connection:
    /// 1. Verifies that the OS routing table still selects the same local source IP to reach
    ///    `peer_addr` (instantly catches DHCP lease changes, Wi-Fi roaming, or interface switches).
    /// 2. Verifies that wall-clock time (`SystemTime`) since the last HTTP/2 `PONG` has not
    ///    exceeded `H2_MAX_PONG_AGE` (instantly catches system suspend/resume where `CLOCK_MONOTONIC`
    ///    froze while the remote proxy or NAT closed the idle connection).
    fn check_viability(&self) -> std::result::Result<(), String> {
        if let (Some(bound_ip), Some(peer)) = (self.local_ip, self.peer_addr) {
            if !bound_ip.is_loopback() && !peer.ip().is_loopback() {
                match current_route_local_ip(peer) {
                    Some(current_ip) if current_ip != bound_ip => {
                        return Err(format!(
                            "local source IP for proxy route changed ({} -> {})",
                            bound_ip, current_ip
                        ));
                    }
                    None => {
                        return Err(format!(
                            "no active OS route to proxy peer {}",
                            peer
                        ));
                    }
                    _ => {}
                }
            }
        }

        if let Ok(last_pong) = self.last_pong_wall.lock() {
            if let Ok(elapsed) = SystemTime::now().duration_since(*last_pong) {
                if elapsed > H2_MAX_PONG_AGE {
                    return Err(format!(
                        "last H2 PONG was {:?} ago (exceeds {:?}; system resume from sleep or stalled link)",
                        elapsed, H2_MAX_PONG_AGE
                    ));
                }
            }
        }

        Ok(())
    }
}

impl Drop for CachedH2Client {
    fn drop(&mut self) {
        self.driver_abort.abort();
        if let Some(ref ping) = self.ping_abort {
            ping.abort();
        }
    }
}

/// Queries the kernel routing table (via an unconnected UDP socket `connect` syscall, which sends
/// zero packets on the wire) to determine the current preferred local source IP for `peer_addr`.
fn current_route_local_ip(peer_addr: SocketAddr) -> Option<IpAddr> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = std::net::UdpSocket::bind(bind_addr).ok()?;
    sock.connect(peer_addr).ok()?;
    Some(sock.local_addr().ok()?.ip())
}

/// Configures kernel-level TCP keepalive and `TCP_USER_TIMEOUT` on the proxy socket so the OS
/// aborts unacknowledged transmissions in ~15 seconds instead of ~16 minutes (`tcp_retries2 = 15`).
#[cfg(target_os = "linux")]
pub(crate) fn configure_proxy_tcp_socket(tcp: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = tcp.as_raw_fd();
    unsafe {
        let user_timeout_ms: libc::c_uint = 15_000;
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
            &user_timeout_ms as *const _ as *const libc::c_void,
            std::mem::size_of_val(&user_timeout_ms) as libc::socklen_t,
        );

        let keepalive: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &keepalive as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepalive) as libc::socklen_t,
        );

        let keepidle: libc::c_int = 30;
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &keepidle as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepidle) as libc::socklen_t,
        );

        let keepintvl: libc::c_int = 10;
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &keepintvl as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepintvl) as libc::socklen_t,
        );

        let keepcnt: libc::c_int = 3;
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &keepcnt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepcnt) as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn configure_proxy_tcp_socket(_tcp: &TcpStream) {}

pub struct Http2MuxTransport {
    proxy_host: String,
    proxy_port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    flow_provider: Arc<dyn FlowMetadataProvider>,
    cached_client: Arc<RwLock<Option<CachedH2Client>>>,
    connecting_lock: Arc<Mutex<()>>,
    next_conn_id: AtomicU64,
    connect_timeout: Duration,
}

impl Http2MuxTransport {
    pub fn new(
        proxy_host: String,
        proxy_port: u16,
        cert_path: Option<PathBuf>,
        key_path: Option<PathBuf>,
        flow_provider: Option<Arc<dyn FlowMetadataProvider>>,
    ) -> Self {
        Self {
            proxy_host,
            proxy_port,
            cert_path,
            key_path,
            flow_provider: flow_provider
                .unwrap_or_else(|| Arc::new(DefaultAcidexProvider::new())),
            cached_client: Arc::new(RwLock::new(None)),
            connecting_lock: Arc::new(Mutex::new(())),
            next_conn_id: AtomicU64::new(1),
            connect_timeout: H2_CONNECT_TIMEOUT,
        }
    }

    async fn try_get_viable_client(&self) -> Option<(u64, h2::client::SendRequest<Bytes>)> {
        let (conn_id, client, viability_err) = {
            let guard = self.cached_client.read().await;
            let cached = guard.as_ref()?;
            (
                cached.conn_id,
                cached.client.clone(),
                cached.check_viability().err(),
            )
        };

        if let Some(reason) = viability_err {
            tracing::warn!(
                "Invalidating stale H2 connection #{}: {}",
                conn_id,
                reason
            );
            self.invalidate_client(conn_id).await;
            return None;
        }

        match tokio::time::timeout(H2_READY_TIMEOUT, client.ready()).await {
            Ok(Ok(ready)) => Some((conn_id, ready)),
            Ok(Err(e)) => {
                tracing::debug!(
                    "Cached H2 connection #{} no longer ready ({:?}); invalidating",
                    conn_id,
                    e
                );
                self.invalidate_client(conn_id).await;
                None
            }
            Err(_) => {
                tracing::warn!(
                    "Timed out waiting for H2 connection #{} ready(); invalidating",
                    conn_id
                );
                self.invalidate_client(conn_id).await;
                None
            }
        }
    }

    async fn get_or_create_client(&self) -> Result<(u64, h2::client::SendRequest<Bytes>)> {
        if let Some(pair) = self.try_get_viable_client().await {
            return Ok(pair);
        }

        let _guard = self.connecting_lock.lock().await;
        // Double check after acquiring connecting_lock
        if let Some(pair) = self.try_get_viable_client().await {
            return Ok(pair);
        }

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            "Establishing new mTLS HTTP/2 connection #{} to {}:{}",
            conn_id,
            self.proxy_host,
            self.proxy_port
        );

        let cert_opt = self.cert_path.as_deref().filter(|p| p.exists());
        let key_opt = self.key_path.as_deref().filter(|p| p.exists());
        let tls_cfg = TlsConfig::for_h2(cert_opt, key_opt);
        let connector = create_ssl_connector(&tls_cfg)?;

        let proxy_host = self.proxy_host.clone();
        let proxy_port = self.proxy_port;

        let (client, mut h2_conn, local_ip, peer_addr) =
            tokio::time::timeout(H2_HANDSHAKE_TIMEOUT, async move {
                let tcp = TcpStream::connect((proxy_host.as_str(), proxy_port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect TCP to {}:{}", proxy_host, proxy_port)
                    })?;
                if let Err(e) = tcp.set_nodelay(true) {
                    tracing::debug!("Failed to set TCP_NODELAY on proxy connection: {:?}", e);
                }
                configure_proxy_tcp_socket(&tcp);

                let local_ip = tcp.local_addr().ok().map(|a| a.ip());
                let peer_addr = tcp.peer_addr().ok();

                let ssl = connector
                    .configure()?
                    .into_ssl(&proxy_host)
                    .context("Failed to configure SSL for proxy")?;

                let mut tls_stream = tokio_openssl::SslStream::new(ssl, tcp)?;
                Pin::new(&mut tls_stream)
                    .connect()
                    .await
                    .context("mTLS handshake failed with Cisco proxy")?;

                let (client, h2_conn) = h2::client::Builder::new()
                    .initial_window_size(1024 * 1024)
                    .initial_connection_window_size(4 * 1024 * 1024)
                    .handshake(tls_stream)
                    .await
                    .context("HTTP/2 handshake failed with Cisco proxy")?;

                Ok::<_, anyhow::Error>((client, h2_conn, local_ip, peer_addr))
            })
            .await
            .with_context(|| {
                format!(
                    "Timed out ({:?}) establishing mTLS HTTP/2 connection to {}:{}",
                    H2_HANDSHAKE_TIMEOUT, self.proxy_host, self.proxy_port
                )
            })??;

        let ping_pong_opt = h2_conn.ping_pong();
        let last_pong_wall = Arc::new(std::sync::Mutex::new(SystemTime::now()));

        // Spawn connection driver task
        let cached_for_driver = Arc::clone(&self.cached_client);
        let driver_task = tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                tracing::debug!("H2 connection #{} driver ended: {:?}", conn_id, e);
            }
            let mut w = cached_for_driver.write().await;
            if w.as_ref().is_some_and(|c| c.conn_id == conn_id) {
                *w = None;
            }
        });
        let driver_abort = driver_task.abort_handle();

        // Spawn PING keepalive task with timeout and automatic stale-connection invalidation
        let ping_abort = if let Some(mut ping_pong) = ping_pong_opt {
            let cached_for_ping = Arc::clone(&self.cached_client);
            let last_pong_for_ping = Arc::clone(&last_pong_wall);
            let ping_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(H2_PING_INTERVAL);
                interval.tick().await; // first tick is immediate
                loop {
                    interval.tick().await;
                    let ping = h2::Ping::opaque();
                    match tokio::time::timeout(H2_PING_TIMEOUT, ping_pong.ping(ping)).await {
                        Ok(Ok(_pong)) => {
                            if let Ok(mut ts) = last_pong_for_ping.lock() {
                                *ts = SystemTime::now();
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                "H2 PING error on connection #{} ({:?}); invalidating connection",
                                conn_id,
                                e
                            );
                            let mut w = cached_for_ping.write().await;
                            if w.as_ref().is_some_and(|c| c.conn_id == conn_id) {
                                *w = None;
                            }
                            break;
                        }
                        Err(_) => {
                            tracing::warn!(
                                "H2 PING keepalive timed out after {:?} on connection #{}; invalidating dead connection",
                                H2_PING_TIMEOUT,
                                conn_id
                            );
                            let mut w = cached_for_ping.write().await;
                            if w.as_ref().is_some_and(|c| c.conn_id == conn_id) {
                                *w = None;
                            }
                            break;
                        }
                    }
                }
            });
            Some(ping_task.abort_handle())
        } else {
            None
        };

        let ready_client = tokio::time::timeout(H2_READY_TIMEOUT, client.clone().ready())
            .await
            .context("Timed out waiting for newly established H2 client ready()")?
            .context("Newly established H2 client failed ready()")?;

        let mut w = self.cached_client.write().await;
        *w = Some(CachedH2Client {
            conn_id,
            client,
            local_ip,
            peer_addr,
            last_pong_wall,
            driver_abort,
            ping_abort,
        });
        Ok((conn_id, ready_client))
    }

    async fn invalidate_client(&self, conn_id: u64) {
        let mut w = self.cached_client.write().await;
        if w.as_ref().is_some_and(|c| c.conn_id == conn_id) {
            *w = None;
        }
    }

    fn build_flow_headers(&self, authority: &str, default_port: u16, src_addr: Option<SocketAddr>) -> (String, u16, HeaderMap) {
        let (host_str, port_num) = if let Some((h, p)) = authority.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        } else {
            (authority.to_string(), default_port)
        };

        let flow_info = FlowInfo {
            src_addr,
            dst_host: host_str.clone(),
            dst_port: port_num,
        };

        let mut headers = HeaderMap::new();
        self.flow_provider.append_headers(&flow_info, &mut headers);
        (host_str, port_num, headers)
    }

    async fn open_h2_stream<F>(
        &self,
        authority: &str,
        proto_label: &str,
        build_request: F,
    ) -> Result<H2TunnelStream>
    where
        F: Fn() -> Result<Request<()>>,
    {
        for attempt in 0..H2_MAX_CONNECT_ATTEMPTS {
            let has_more_attempts = attempt + 1 < H2_MAX_CONNECT_ATTEMPTS;
            let (conn_id, mut ready_client) = self.get_or_create_client().await?;
            let request = build_request()?;

            let (response_future, send_stream) = match ready_client.send_request(request, false) {
                Ok(pair) => pair,
                Err(e) => {
                    self.invalidate_client(conn_id).await;
                    if has_more_attempts {
                        tracing::warn!(
                            "Failed to send {} on cached H2 connection #{} for {} ({:?}); reconnecting and retrying ({}/{})",
                            proto_label,
                            conn_id,
                            authority,
                            e,
                            attempt + 1,
                            H2_MAX_CONNECT_ATTEMPTS
                        );
                        continue;
                    }
                    bail!("Failed to send {} request: {:?}", proto_label, e);
                }
            };

            let attempt_timeout = if has_more_attempts {
                std::cmp::min(self.connect_timeout, H2_FAST_CONNECT_TIMEOUT)
            } else {
                self.connect_timeout
            };

            let response = match tokio::time::timeout(attempt_timeout, response_future).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    if e.is_io() || e.is_go_away() || e.is_library() || e.is_remote() {
                        self.invalidate_client(conn_id).await;
                        if has_more_attempts {
                            tracing::warn!(
                                "H2 connection #{} error awaiting {} response for {} ({:?}); reconnecting and retrying ({}/{})",
                                conn_id,
                                proto_label,
                                authority,
                                e,
                                attempt + 1,
                                H2_MAX_CONNECT_ATTEMPTS
                            );
                            continue;
                        }
                    }
                    bail!("{} response error: {:?}", proto_label, e);
                }
                Err(_) => {
                    drop(send_stream);
                    if attempt == 0 && has_more_attempts {
                        tracing::warn!(
                            "Timed out ({:?}) awaiting HTTP/2 {} response for {} on connection #{} (attempt {}/{}); cancelling stream and retrying on a new stream",
                            attempt_timeout,
                            proto_label,
                            authority,
                            conn_id,
                            attempt + 1,
                            H2_MAX_CONNECT_ATTEMPTS
                        );
                        continue;
                    }
                    self.invalidate_client(conn_id).await;
                    if has_more_attempts {
                        tracing::warn!(
                            "Timed out ({:?}) awaiting HTTP/2 {} response for {} on connection #{}; reconnecting and retrying ({}/{})",
                            attempt_timeout,
                            proto_label,
                            authority,
                            conn_id,
                            attempt + 1,
                            H2_MAX_CONNECT_ATTEMPTS
                        );
                        continue;
                    }
                    bail!(
                        "Timed out ({:?}) awaiting HTTP/2 {} response for {}",
                        attempt_timeout,
                        proto_label,
                        authority
                    );
                }
            };

            let status = response.status();
            tracing::info!("{} response status for {}: {}", proto_label, authority, status);

            if status == http::StatusCode::OK {
                let (_, recv_stream) = response.into_parts();
                return Ok(H2TunnelStream::new(send_stream, recv_stream));
            } else if is_retryable_gateway_status(status) && has_more_attempts {
                tracing::warn!(
                    "HTTP/2 {} for {} returned transient gateway status {} (attempt {}/{}); retrying on a new stream",
                    proto_label,
                    authority,
                    status,
                    attempt + 1,
                    H2_MAX_CONNECT_ATTEMPTS
                );
                continue;
            } else if status == http::StatusCode::FORBIDDEN {
                bail!(
                    "HTTP/2 {} forbidden (403) by Cisco ZTNA policy for {}",
                    proto_label,
                    authority
                );
            } else if status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                bail!(
                    "HTTP/2 {} proxy authentication required (407) for {}",
                    proto_label,
                    authority
                );
            } else {
                bail!(
                    "HTTP/2 {} rejected with status {} for {}",
                    proto_label,
                    status,
                    authority
                );
            }
        }

        unreachable!()
    }

    pub async fn open_tcp_tunnel(
        &self,
        authority: &str,
        src_addr: Option<SocketAddr>,
    ) -> Result<H2TunnelStream> {
        let (_, _, headers) = self.build_flow_headers(authority, 443, src_addr);
        tracing::info!("Sending HTTP/2 CONNECT to authority {}", authority);

        self.open_h2_stream(authority, "CONNECT", || {
            let mut req = Request::builder().method(Method::CONNECT).uri(authority);
            for (k, v) in headers.iter() {
                req = req.header(k, v);
            }
            Ok(req.body(())?)
        })
        .await
    }

    /// Relays a tunneled TCP stream with automatic initial-handshake retry if the first HTTP/2
    /// stream hits an unresponsive ZTA Connector (closing with 0 bytes or timing out before the
    /// first server response byte arrives).
    pub async fn relay_tcp_stream<A>(
        &self,
        local: &mut A,
        initial_tunnel: H2TunnelStream,
        authority: &str,
        src_addr: Option<SocketAddr>,
    ) -> io::Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        relay_bidirectional_with_retry(local, initial_tunnel, authority, || {
            self.open_tcp_tunnel(authority, src_addr)
        })
        .await
    }

    /// Opens an Extended CONNECT (`CONNECT-UDP`, RFC 8441 / RFC 9298 MASQUE) stream over HTTP/2.
    pub async fn open_udp_tunnel(
        &self,
        authority: &str,
        src_addr: Option<SocketAddr>,
    ) -> Result<H2UdpStream> {
        let (host_str, port_num, headers) = self.build_flow_headers(authority, 53, src_addr);
        let masque_uri = format!(
            "https://{}/.well-known/masque/udp/{}/{}/",
            self.proxy_host, host_str, port_num
        );
        tracing::info!(
            "Sending HTTP/2 Extended CONNECT (CONNECT-UDP) for {} via {}",
            authority,
            masque_uri
        );

        let stream = self
            .open_h2_stream(authority, "CONNECT-UDP", || {
                let mut req = Request::builder()
                    .method(Method::CONNECT)
                    .uri(&masque_uri)
                    .version(Version::HTTP_2);
                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }
                let mut request = req.body(())?;
                request
                    .extensions_mut()
                    .insert(h2::ext::Protocol::from_static("CONNECT-UDP"));
                Ok(request)
            })
            .await?;

        Ok(H2UdpStream::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cached_h2_client_detects_sleep_and_aborts_stuck_connect() {
        let (client_io, _blackholed_server_io) = tokio::io::duplex(64 * 1024);
        let (server_wire, server_io) = tokio::io::duplex(64 * 1024);

        // Perform a real H2 handshake first, then stop reading from server_io to simulate a post-sleep blackhole
        let handshake_bridge = tokio::spawn(async move {
            let server = h2::server::handshake(server_io).await.unwrap();
            // Keep server alive without answering any CONNECT requests (simulating blackhole)
            std::future::pending::<()>().await;
            drop(server);
        });

        let (mut c_a, mut c_b) = tokio::io::split(client_io);
        let (mut s_a, mut s_b) = tokio::io::split(server_wire);
        let bridge_task = tokio::spawn(async move {
            let _ = tokio::join!(
                tokio::io::copy(&mut c_a, &mut s_b),
                tokio::io::copy(&mut s_a, &mut c_b)
            );
        });

        let (client, h2_conn) = h2::client::handshake(_blackholed_server_io).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let last_pong_wall = Arc::new(std::sync::Mutex::new(SystemTime::now()));
        let cached = CachedH2Client {
            conn_id: 1,
            client: client.clone(),
            local_ip: None,
            peer_addr: None,
            last_pong_wall: Arc::clone(&last_pong_wall),
            driver_abort: driver_task.abort_handle(),
            ping_abort: Some(bridge_task.abort_handle()),
        };

        // Initially viable
        assert!(cached.check_viability().is_ok());

        // Simulate system resume from sleep (wall-clock advanced beyond H2_MAX_PONG_AGE)
        *last_pong_wall.lock().unwrap() =
            SystemTime::now() - (H2_MAX_PONG_AGE + Duration::from_secs(10));
        let err_msg = cached.check_viability().unwrap_err();
        assert!(err_msg.contains("last H2 PONG was"), "Unexpected error: {}", err_msg);

        // Queue a CONNECT request on the blackholed connection
        let mut ready = client.clone().ready().await.unwrap();
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("gitlab.vstbank.ua:443")
            .body(())
            .unwrap();
        let (resp_fut, _send_stream) = ready.send_request(req, false).unwrap();

        // Dropping CachedH2Client (on invalidation) must abort the driver task immediately,
        // causing in-flight `resp_fut` to resolve with an error right away instead of hanging.
        drop(cached);
        drop(ready);
        drop(client);

        let res = tokio::time::timeout(Duration::from_millis(200), resp_fut)
            .await
            .expect("resp_fut should fail immediately when driver is aborted");
        assert!(res.is_err());

        handshake_bridge.abort();
    }

    #[test]
    fn test_is_retryable_gateway_status() {
        assert!(is_retryable_gateway_status(http::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_gateway_status(
            http::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(is_retryable_gateway_status(
            http::StatusCode::GATEWAY_TIMEOUT
        ));
        assert!(!is_retryable_gateway_status(http::StatusCode::OK));
        assert!(!is_retryable_gateway_status(http::StatusCode::FORBIDDEN));
        assert!(!is_retryable_gateway_status(
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        ));
    }
}
