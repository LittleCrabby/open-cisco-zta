use bytes::{Buf, Bytes};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Interval for sending 0-byte HTTP/2 `DATA` frames on idle tunnel streams so that
/// Cisco ZPC Envoy proxies reset their per-stream `stream_idle_timeout` even when OS
/// TCP keep-alives are terminated locally by the userspace TUN netstack.
pub const STREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(28);

/// Bidirectional `AsyncRead` / `AsyncWrite` wrapper around an HTTP/2 `CONNECT` or
/// `CONNECT-UDP` stream with immediate receive-window release and idle keepalives.
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Request};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_h2_tunnel_stream_sends_keepalive_data_frame() {
        let (client_io, mut raw_wire) = tokio::io::duplex(64 * 1024);
        let (mut server_wire, server_io) = tokio::io::duplex(64 * 1024);

        let data_frames_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
}
