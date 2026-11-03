use crate::crypto::{create_ssl_connector, TlsConfig};
use crate::plugins::{DefaultAcidexProvider, FlowInfo, FlowMetadataProvider};
use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, Method, Request, Version};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};

pub struct Http2MuxTransport {
    proxy_host: String,
    proxy_port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    flow_provider: Arc<dyn FlowMetadataProvider>,
    send_request: Arc<RwLock<Option<h2::client::SendRequest<Bytes>>>>,
    connecting_lock: Arc<Mutex<()>>,
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
            send_request: Arc::new(RwLock::new(None)),
            connecting_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn get_or_create_client(&self) -> Result<h2::client::SendRequest<Bytes>> {
        {
            let guard = self.send_request.read().await;
            if let Some(ref client) = *guard {
                if let Ok(ready) = client.clone().ready().await {
                    return Ok(ready);
                }
            }
        }

        let _guard = self.connecting_lock.lock().await;
        // Double check after lock
        {
            let guard = self.send_request.read().await;
            if let Some(ref client) = *guard {
                if let Ok(ready) = client.clone().ready().await {
                    return Ok(ready);
                }
            }
        }

        tracing::info!(
            "Establishing new mTLS HTTP/2 connection to {}:{}",
            self.proxy_host,
            self.proxy_port
        );

        let cert_opt = self.cert_path.as_deref().filter(|p| p.exists());
        let key_opt = self.key_path.as_deref().filter(|p| p.exists());
        let tls_cfg = TlsConfig::for_h2(cert_opt, key_opt);
        let connector = create_ssl_connector(&tls_cfg)?;

        let tcp = TcpStream::connect((self.proxy_host.as_str(), self.proxy_port))
            .await
            .with_context(|| format!("Failed to connect TCP to {}:{}", self.proxy_host, self.proxy_port))?;
        if let Err(e) = tcp.set_nodelay(true) {
            tracing::debug!("Failed to set TCP_NODELAY on proxy connection: {:?}", e);
        }

        let ssl = connector
            .configure()?
            .into_ssl(&self.proxy_host)
            .context("Failed to configure SSL for proxy")?;

        let mut tls_stream = tokio_openssl::SslStream::new(ssl, tcp)?;
        Pin::new(&mut tls_stream)
            .connect()
            .await
            .context("mTLS handshake failed with Cisco proxy")?;

        let (client, mut h2_conn) = h2::client::Builder::new()
            .initial_window_size(1024 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024)
            .handshake(tls_stream)
            .await
            .context("HTTP/2 handshake failed with Cisco proxy")?;

        let ping_pong_opt = h2_conn.ping_pong();

        // Spawn connection driver task
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                tracing::debug!("H2 connection driver ended: {:?}", e);
            }
        });

        // Spawn PING keepalive task
        if let Some(mut ping_pong) = ping_pong_opt {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.tick().await; // first tick is immediate
                loop {
                    interval.tick().await;
                    let ping = h2::Ping::opaque();
                    if let Err(e) = ping_pong.ping(ping).await {
                        tracing::debug!("H2 PING error (connection likely closed): {:?}", e);
                        break;
                    }
                }
            });
        }

        let mut w = self.send_request.write().await;
        *w = Some(client.clone());
        Ok(client)
    }

    async fn invalidate_client(&self) {
        let mut w = self.send_request.write().await;
        *w = None;
    }

    pub async fn open_tcp_tunnel(
        &self,
        authority: &str,
        src_addr: Option<SocketAddr>,
    ) -> Result<H2TunnelStream> {
        let (host_str, port_num) = if let Some((h, p)) = authority.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (authority.to_string(), 443)
        };

        let flow_info = FlowInfo {
            src_addr,
            dst_host: host_str,
            dst_port: port_num,
        };

        let mut headers = HeaderMap::new();
        self.flow_provider.append_headers(&flow_info, &mut headers);

        for attempt in 0..2 {
            let client = self.get_or_create_client().await?;
            let mut ready_client = match client.ready().await {
                Ok(c) => c,
                Err(e) => {
                    self.invalidate_client().await;
                    if attempt == 0 {
                        tracing::warn!(
                            "Cached H2 client not ready for {} ({:?}); reconnecting and retrying",
                            authority,
                            e
                        );
                        continue;
                    }
                    bail!("H2 client not ready: {:?}", e);
                }
            };

            let mut req = Request::builder()
                .method(Method::CONNECT)
                .uri(authority);

            for (k, v) in headers.iter() {
                req = req.header(k, v);
            }

            let request = req.body(())?;
            tracing::info!("Sending HTTP/2 CONNECT to authority {}", authority);

            let (response_future, send_stream) = match ready_client.send_request(request, false) {
                Ok(pair) => pair,
                Err(e) => {
                    self.invalidate_client().await;
                    if attempt == 0 {
                        tracing::warn!(
                            "Failed to send CONNECT on cached H2 connection for {} ({:?}); reconnecting and retrying",
                            authority,
                            e
                        );
                        continue;
                    }
                    bail!("Failed to send CONNECT request: {:?}", e);
                }
            };

            let response = match response_future.await {
                Ok(resp) => resp,
                Err(e) => {
                    if e.is_io() || e.is_go_away() || e.is_library() {
                        self.invalidate_client().await;
                        if attempt == 0 {
                            tracing::warn!(
                                "H2 connection error awaiting CONNECT response for {} ({:?}); reconnecting and retrying",
                                authority,
                                e
                            );
                            continue;
                        }
                    }
                    bail!("CONNECT response error: {:?}", e);
                }
            };

            let status = response.status();
            tracing::info!("CONNECT response status for {}: {}", authority, status);

            if status == http::StatusCode::OK {
                let (_, recv_stream) = response.into_parts();
                return Ok(H2TunnelStream::new(send_stream, recv_stream));
            } else if status == http::StatusCode::FORBIDDEN {
                bail!("HTTP/2 CONNECT forbidden (403) by Cisco ZTNA policy for {}", authority);
            } else if status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                bail!("HTTP/2 CONNECT proxy authentication required (407) for {}", authority);
            } else {
                bail!("HTTP/2 CONNECT rejected with status {} for {}", status, authority);
            }
        }

        unreachable!()
    }

    /// Opens an Extended CONNECT (`CONNECT-UDP`, RFC 8441 / RFC 9298 MASQUE) stream over HTTP/2.
    pub async fn open_udp_tunnel(
        &self,
        authority: &str,
        src_addr: Option<SocketAddr>,
    ) -> Result<H2UdpStream> {
        let (host_str, port_num) = if let Some((h, p)) = authority.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(53))
        } else {
            (authority.to_string(), 53)
        };

        let flow_info = FlowInfo {
            src_addr,
            dst_host: host_str.clone(),
            dst_port: port_num,
        };

        let masque_uri = format!(
            "https://{}/.well-known/masque/udp/{}/{}/",
            self.proxy_host, host_str, port_num
        );

        let mut headers = HeaderMap::new();
        self.flow_provider.append_headers(&flow_info, &mut headers);

        for attempt in 0..2 {
            let client = self.get_or_create_client().await?;
            let mut ready_client = match client.ready().await {
                Ok(c) => c,
                Err(e) => {
                    self.invalidate_client().await;
                    if attempt == 0 {
                        tracing::warn!(
                            "Cached H2 client not ready for UDP {} ({:?}); reconnecting and retrying",
                            authority,
                            e
                        );
                        continue;
                    }
                    bail!("H2 client not ready: {:?}", e);
                }
            };

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

            tracing::info!(
                "Sending HTTP/2 Extended CONNECT (CONNECT-UDP) for {} via {}",
                authority,
                masque_uri
            );

            let (response_future, send_stream) = match ready_client.send_request(request, false) {
                Ok(pair) => pair,
                Err(e) => {
                    self.invalidate_client().await;
                    if attempt == 0 {
                        tracing::warn!(
                            "Failed to send CONNECT-UDP on cached H2 connection for {} ({:?}); reconnecting and retrying",
                            authority,
                            e
                        );
                        continue;
                    }
                    bail!("Failed to send CONNECT-UDP request: {:?}", e);
                }
            };

            let response = match response_future.await {
                Ok(resp) => resp,
                Err(e) => {
                    if e.is_io() || e.is_go_away() || e.is_library() {
                        self.invalidate_client().await;
                        if attempt == 0 {
                            tracing::warn!(
                                "H2 connection error awaiting CONNECT-UDP response for {} ({:?}); reconnecting and retrying",
                                authority,
                                e
                            );
                            continue;
                        }
                    }
                    bail!("CONNECT-UDP response error: {:?}", e);
                }
            };

            let status = response.status();
            tracing::info!("CONNECT-UDP response status for {}: {}", authority, status);

            if status == http::StatusCode::OK {
                let (_, recv_stream) = response.into_parts();
                return Ok(H2UdpStream::new(H2TunnelStream::new(
                    send_stream,
                    recv_stream,
                )));
            } else if status == http::StatusCode::FORBIDDEN {
                bail!(
                    "HTTP/2 CONNECT-UDP forbidden (403) by Cisco ZTNA policy for {}",
                    authority
                );
            } else if status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                bail!(
                    "HTTP/2 CONNECT-UDP proxy authentication required (407) for {}",
                    authority
                );
            } else {
                bail!(
                    "HTTP/2 CONNECT-UDP rejected with status {} for {}",
                    status,
                    authority
                );
            }
        }

        unreachable!()
    }
}

/// Encodes a QUIC variable-length integer (RFC 9000 Section 16) into `buf`.
pub fn put_quic_varint(buf: &mut BytesMut, val: u64) -> Result<()> {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16_384 {
        buf.put_u16((val as u16) | 0x4000);
    } else if val < 1_073_741_824 {
        buf.put_u32((val as u32) | 0x8000_0000);
    } else if val < 4_611_686_018_427_387_904 {
        buf.put_u64(val | 0xc000_0000_0000_0000);
    } else {
        bail!("Value {} exceeds maximum 62-bit QUIC varint", val);
    }
    Ok(())
}

/// Peeks a QUIC variable-length integer (RFC 9000 Section 16) from the start of `slice`,
/// returning `Some((value, encoded_byte_len))` if enough bytes are available, or `None` if incomplete.
pub fn peek_quic_varint(slice: &[u8]) -> Option<(u64, usize)> {
    let first = *slice.first()?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if slice.len() < len {
        return None;
    }
    let val = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&slice[..2]);
            b[0] &= 0x3f;
            u16::from_be_bytes(b) as u64
        }
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&slice[..4]);
            b[0] &= 0x3f;
            u32::from_be_bytes(b) as u64
        }
        8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&slice[..8]);
            b[0] &= 0x3f;
            u64::from_be_bytes(b)
        }
        _ => unreachable!(),
    };
    Some((val, len))
}

/// Encodes a raw UDP payload into an RFC 9297 / RFC 9298 HTTP `DATAGRAM` capsule
/// (`Capsule Type = 0x00`, `Capsule Length = varint(1 + payload.len())`, `Context ID = 0x00`, `Payload`).
pub fn encode_udp_capsule(payload: &[u8]) -> Result<Bytes> {
    let capsule_len = (1 + payload.len()) as u64;
    let mut buf = BytesMut::with_capacity(10 + payload.len());
    // Capsule Type = 0x00 (DATAGRAM)
    buf.put_u8(0x00);
    // Capsule Length = 1 (Context ID) + payload.len()
    put_quic_varint(&mut buf, capsule_len)?;
    // Context ID = 0x00 (UDP payload)
    buf.put_u8(0x00);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// Attempts to decode the next UDP `DATAGRAM` capsule (Context ID 0) from `buf`.
/// Unknown capsule types or non-zero Context IDs are skipped per RFC 9297 / RFC 9298.
/// Returns `Ok(None)` if `buf` does not yet contain a complete capsule.
pub fn try_decode_udp_capsule(buf: &mut BytesMut) -> Result<Option<Bytes>> {
    loop {
        if buf.is_empty() {
            return Ok(None);
        }
        let (capsule_type, type_len) = match peek_quic_varint(buf) {
            Some(v) => v,
            None => return Ok(None),
        };
        let (capsule_len, len_len) = match peek_quic_varint(&buf[type_len..]) {
            Some(v) => v,
            None => return Ok(None),
        };
        // Guard against unreasonable capsule sizes (> 64 KiB for UDP datagrams)
        if capsule_len > 65_536 {
            bail!(
                "Invalid HTTP datagram capsule length {} (type {})",
                capsule_len,
                capsule_type
            );
        }
        let header_len = type_len + len_len;
        let total_len = header_len + (capsule_len as usize);
        if buf.len() < total_len {
            return Ok(None);
        }

        buf.advance(header_len);
        let mut body = buf.split_to(capsule_len as usize);

        if capsule_type == 0x00 {
            let (context_id, ctx_len) = match peek_quic_varint(&body) {
                Some(v) => v,
                None => bail!("Malformed empty DATAGRAM capsule missing Context ID"),
            };
            body.advance(ctx_len);
            if context_id == 0x00 {
                return Ok(Some(body.freeze()));
            } else {
                tracing::debug!(
                    "Ignoring DATAGRAM capsule with non-zero Context ID {}",
                    context_id
                );
            }
        } else {
            tracing::debug!("Ignoring unknown HTTP capsule type {}", capsule_type);
        }
    }
}

/// High-level wrapper around an `H2TunnelStream` negotiated with `CONNECT-UDP`
/// that frames and deframes UDP datagrams using RFC 9297 / RFC 9298 HTTP Capsules.
pub struct H2UdpStream {
    inner: H2TunnelStream,
    read_buf: BytesMut,
}

impl H2UdpStream {
    pub fn new(inner: H2TunnelStream) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(8192),
        }
    }

    pub async fn send_datagram(&mut self, payload: &[u8]) -> Result<()> {
        let capsule = encode_udp_capsule(payload)?;
        self.inner
            .write_all(&capsule)
            .await
            .context("Failed to write UDP capsule to H2 stream")?;
        Ok(())
    }

    pub async fn recv_datagram(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(datagram) = try_decode_udp_capsule(&mut self.read_buf)? {
                return Ok(Some(datagram));
            }
            let n = self
                .inner
                .read_buf(&mut self.read_buf)
                .await
                .context("Failed to read UDP capsule from H2 stream")?;
            if n == 0 {
                return Ok(None);
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let _ = self.inner.shutdown().await;
        Ok(())
    }
}

/// Interval for sending 0-byte HTTP/2 `DATA` frames on idle tunnel streams so that
/// Cisco ZPC Envoy proxies reset their per-stream `stream_idle_timeout` even when OS
/// TCP keep-alives are terminated locally by the userspace TUN netstack.
const STREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(28);

/// Maximum time to wait for the opposite direction to finish after one side of a
/// tunneled TCP connection sends `EOF` (`FIN` / `END_STREAM`). Prevents tasks and
/// HTTP/2 streams from leaking when a local application leaves sockets in `CLOSE-WAIT`.
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct H2TunnelStream {
    send_stream: h2::SendStream<Bytes>,
    recv_stream: h2::RecvStream,
    read_buf: Option<Bytes>,
    eof_sent: bool,
    keepalive_interval: Duration,
    keepalive_sleep: Pin<Box<tokio::time::Sleep>>,
}

impl H2TunnelStream {
    pub fn new(send_stream: h2::SendStream<Bytes>, recv_stream: h2::RecvStream) -> Self {
        Self::with_keepalive_interval(send_stream, recv_stream, STREAM_KEEPALIVE_INTERVAL)
    }

    pub fn with_keepalive_interval(
        send_stream: h2::SendStream<Bytes>,
        recv_stream: h2::RecvStream,
        keepalive_interval: Duration,
    ) -> Self {
        Self {
            send_stream,
            recv_stream,
            read_buf: None,
            eof_sent: false,
            keepalive_interval,
            keepalive_sleep: Box::pin(tokio::time::sleep(keepalive_interval)),
        }
    }
}

impl AsyncRead for H2TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // First consume remaining bytes in read_buf
            if let Some(mut current) = self.read_buf.take() {
                if !current.is_empty() {
                    let to_copy = std::cmp::min(buf.remaining(), current.len());
                    buf.put_slice(&current[..to_copy]);
                    current.advance(to_copy);
                    if !current.is_empty() {
                        self.read_buf = Some(current);
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // Receive next data frame
            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    if len > 0 {
                        // Crucial: release capacity to keep HTTP/2 WINDOW_UPDATE flowing!
                        if let Err(e) = self.recv_stream.flow_control().release_capacity(len) {
                            tracing::warn!("Failed to release H2 capacity: {:?}", e);
                        }
                        self.read_buf = Some(data);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => {
                    // EOF
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    if !self.eof_sent && self.keepalive_sleep.as_mut().poll(cx).is_ready() {
                        let interval = self.keepalive_interval;
                        self.keepalive_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + interval);
                        let _ = self.keepalive_sleep.as_mut().poll(cx);
                        if let Err(e) = self.send_stream.send_data(Bytes::new(), false) {
                            tracing::debug!(
                                "H2 stream keepalive send_data failed (stream likely closed): {:?}",
                                e
                            );
                        } else {
                            tracing::trace!(
                                "Sent 0-byte HTTP/2 DATA keepalive frame on tunnel stream"
                            );
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for H2TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            if self.send_stream.capacity() == 0 {
                self.send_stream.reserve_capacity(buf.len());
            }

            match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(0))) => {
                    self.send_stream.reserve_capacity(buf.len());
                    continue;
                }
                Poll::Ready(Some(Ok(capacity))) => {
                    let to_send = std::cmp::min(capacity, buf.len());
                    let bytes = Bytes::copy_from_slice(&buf[..to_send]);
                    if let Err(e) = self.send_stream.send_data(bytes, false) {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    let interval = self.keepalive_interval;
                    self.keepalive_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + interval);
                    let _ = self.keepalive_sleep.as_mut().poll(cx);
                    return Poll::Ready(Ok(to_send));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.eof_sent {
            if let Err(e) = self.send_stream.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            self.eof_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

/// Relays data bidirectionally between `a` (local client stream) and `b` (remote tunnel stream)
/// without blocking indefinitely when one side closes (`EOF`) while the other stays in `CLOSE-WAIT`.
///
/// Specifically, `netstack_smoltcp::TcpStream::poll_shutdown` initiates `FIN` on the first call
/// (`control.send_state = TcpSocketState::Close`) and then returns `Poll::Pending` until the local
/// client also closes its write half (`TcpState::Closed`). Standard `tokio::io::copy_bidirectional`
/// hangs forever on `poll_shutdown` if a client (such as an idle JDBC pool in `CLOSE-WAIT`) does
/// not immediately close its socket. This function initiates write-shutdown as soon as one side
/// reaches `EOF` and bounds the remaining half-close drain to `HALF_CLOSE_TIMEOUT`.
pub async fn relay_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    relay_bidirectional_with_timeout(a, b, HALF_CLOSE_TIMEOUT).await
}

pub async fn relay_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    half_close_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf_ab = vec![0u8; 16 * 1024];
    let mut pos_ab = 0usize;
    let mut cap_ab = 0usize;
    let mut done_ab = false;
    let mut total_ab = 0u64;

    let mut buf_ba = vec![0u8; 16 * 1024];
    let mut pos_ba = 0usize;
    let mut cap_ba = 0usize;
    let mut done_ba = false;
    let mut total_ba = 0u64;

    let mut half_close_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;

    futures::future::poll_fn(|cx| {
        // Direction 1: a -> b
        while !done_ab {
            if pos_ab < cap_ab {
                match Pin::new(&mut *b).poll_write(cx, &buf_ab[pos_ab..cap_ab]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into tunnel",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        pos_ab += n;
                        total_ab += n as u64;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        let _ = Pin::new(&mut *b).poll_flush(cx);
                        break;
                    }
                }
            }

            pos_ab = 0;
            cap_ab = 0;
            let mut read_buf = ReadBuf::new(&mut buf_ab);
            match Pin::new(&mut *a).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        let _ = Pin::new(&mut *b).poll_flush(cx);
                        let _ = Pin::new(&mut *b).poll_shutdown(cx);
                        done_ab = true;
                        if half_close_sleep.is_none() && !done_ba {
                            half_close_sleep =
                                Some(Box::pin(tokio::time::sleep(half_close_timeout)));
                        }
                    } else {
                        cap_ab = n;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    let _ = Pin::new(&mut *b).poll_flush(cx);
                    break;
                }
            }
        }

        // Direction 2: b -> a
        while !done_ba {
            if pos_ba < cap_ba {
                match Pin::new(&mut *a).poll_write(cx, &buf_ba[pos_ba..cap_ba]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into local stream",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        pos_ba += n;
                        total_ba += n as u64;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        let _ = Pin::new(&mut *a).poll_flush(cx);
                        break;
                    }
                }
            }

            pos_ba = 0;
            cap_ba = 0;
            let mut read_buf = ReadBuf::new(&mut buf_ba);
            match Pin::new(&mut *b).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        let _ = Pin::new(&mut *a).poll_flush(cx);
                        let _ = Pin::new(&mut *a).poll_shutdown(cx);
                        done_ba = true;
                        if half_close_sleep.is_none() && !done_ab {
                            half_close_sleep =
                                Some(Box::pin(tokio::time::sleep(half_close_timeout)));
                        }
                    } else {
                        cap_ba = n;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    let _ = Pin::new(&mut *a).poll_flush(cx);
                    break;
                }
            }
        }

        if done_ab && done_ba {
            return Poll::Ready(Ok((total_ab, total_ba)));
        }

        if let Some(ref mut sleep) = half_close_sleep {
            if sleep.as_mut().poll(cx).is_ready() {
                if !done_ab {
                    let _ = Pin::new(&mut *b).poll_shutdown(cx);
                }
                if !done_ba {
                    let _ = Pin::new(&mut *a).poll_shutdown(cx);
                }
                return Poll::Ready(Ok((total_ab, total_ba)));
            }
        }

        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_varint_roundtrip() {
        for &(val, expected_len) in &[
            (0u64, 1usize),
            (37, 1),
            (63, 1),
            (64, 2),
            (15293, 2),
            (16383, 2),
            (16384, 4),
            (494_878_333, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (151_288_809_941_952_652, 8),
        ] {
            let mut buf = BytesMut::new();
            put_quic_varint(&mut buf, val).unwrap();
            assert_eq!(buf.len(), expected_len);
            let (decoded, len) = peek_quic_varint(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, expected_len);
        }
    }

    #[test]
    fn test_udp_capsule_small_and_medium_roundtrip() {
        // Small payload (< 63 bytes -> 1-byte length varint)
        let small_payload = b"hello kerberos kdc";
        let capsule = encode_udp_capsule(small_payload).unwrap();
        assert_eq!(capsule[0], 0x00); // Capsule Type = DATAGRAM (0)
        assert_eq!(capsule[1], (1 + small_payload.len()) as u8); // 1-byte varint length
        assert_eq!(capsule[2], 0x00); // Context ID = 0
        assert_eq!(&capsule[3..], small_payload);

        let mut rx_buf = BytesMut::from(&capsule[..]);
        let decoded = try_decode_udp_capsule(&mut rx_buf).unwrap().unwrap();
        assert_eq!(&decoded[..], small_payload);
        assert!(rx_buf.is_empty());

        // Medium payload (e.g., 1400-byte Kerberos ticket -> 2-byte length varint)
        let med_payload = vec![0xab; 1400];
        let med_capsule = encode_udp_capsule(&med_payload).unwrap();
        assert_eq!(med_capsule[0], 0x00);
        // 1401 = 0x0579 -> with 0x4000 prefix = 0x45, 0x79
        assert_eq!(med_capsule[1], 0x45);
        assert_eq!(med_capsule[2], 0x79);
        assert_eq!(med_capsule[3], 0x00);

        // Test fragmented arrival + coalesced capsules
        let mut stream_buf = BytesMut::new();
        stream_buf.extend_from_slice(&med_capsule[..10]);
        assert!(try_decode_udp_capsule(&mut stream_buf).unwrap().is_none());
        stream_buf.extend_from_slice(&med_capsule[10..]);
        stream_buf.extend_from_slice(&capsule);

        let d1 = try_decode_udp_capsule(&mut stream_buf).unwrap().unwrap();
        assert_eq!(&d1[..], &med_payload[..]);
        let d2 = try_decode_udp_capsule(&mut stream_buf).unwrap().unwrap();
        assert_eq!(&d2[..], small_payload);
        assert!(try_decode_udp_capsule(&mut stream_buf).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_h2_tunnel_stream_sends_keepalive_data_frame() {
        let (client_io, mut raw_wire) = tokio::io::duplex(64 * 1024);
        let (mut server_wire, server_io) = tokio::io::duplex(64 * 1024);

        let data_frames_seen = Arc::new( std::sync::atomic::AtomicUsize::new(0));
        let data_frames_seen_clone = Arc::clone(&data_frames_seen);

        // Proxy raw bytes between client_io and server_io and count 9-byte empty
        // HTTP/2 DATA frames for Stream ID 1: [0, 0, 0, 0, 0, 0, 0, 0, 1]
        tokio::spawn(async move {
            let (mut r_c, mut w_c) = tokio::io::split(&mut raw_wire);
            let (mut r_s, mut w_s) = tokio::io::split(&mut server_wire);
            let c_to_s = async {
                let mut buf = [0u8; 4096];
                while let Ok(n) = r_c.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    // Look for 9-byte empty DATA frame header on stream 1:
                    // Length = 0x000000 (3 bytes), Type = 0x00 (DATA), Flags = 0x00, Stream ID = 0x00000001
                    let empty_data_frame = [0u8, 0, 0, 0, 0, 0, 0, 0, 1];
                    if buf[..n]
                        .windows(empty_data_frame.len())
                        .any(|w| w == empty_data_frame)
                    {
                        data_frames_seen_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    if w_s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            };
            let s_to_c = tokio::io::copy(&mut r_s, &mut w_c);
            let _ = tokio::join!(c_to_s, s_to_c);
        });

        let server_task = tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let (_req, mut respond) = server.accept().await.unwrap().unwrap();
            let resp = http::Response::builder().status(200).body(()).unwrap();
            let _send = respond.send_response(resp, false).unwrap();
            while server.accept().await.is_some() {}
        });

        let (client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let mut ready = client.ready().await.unwrap();
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("sqltest.bank.lan:1433")
            .body(())
            .unwrap();
        let (resp_fut, send_stream) = ready.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        let (_, recv_stream) = resp.into_parts();
        let mut tunnel = H2TunnelStream::with_keepalive_interval(
            send_stream,
            recv_stream,
            Duration::from_millis(15),
        );

        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(60), tunnel.read(&mut buf)).await;
        drop(tunnel);
        drop(ready);
        let _ = server_task.await;

        assert!(
            data_frames_seen.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "Expected at least one 0-byte HTTP/2 DATA keepalive frame on the wire"
        );
    }

    #[tokio::test]
    async fn test_relay_bidirectional_bounds_close_wait() {
        // Simulate a local stream whose peer stays in CLOSE-WAIT (never sends EOF)
        // when the remote tunnel closes first.
        let (mut local_client, _local_app_kept_open) = tokio::io::duplex(1024);
        let (mut tunnel_client, mut tunnel_server) = tokio::io::duplex(1024);

        tunnel_server.write_all(b"server greeting").await.unwrap();
        drop(tunnel_server); // Remote closes tunnel (EOF)

        let (ab, ba) = relay_bidirectional_with_timeout(
            &mut local_client,
            &mut tunnel_client,
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        assert_eq!(ab, 0);
        assert_eq!(ba, b"server greeting".len() as u64);
    }
}
