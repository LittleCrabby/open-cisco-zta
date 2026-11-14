use anyhow::Result;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Maximum time to wait for the opposite direction to finish after one side of a
/// tunneled TCP connection sends `EOF` (`FIN` / `END_STREAM`). Prevents tasks and
/// HTTP/2 streams from leaking when a local application leaves sockets in `CLOSE-WAIT`.
pub const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for the first server response byte after the client sends its
/// initial handshake payload (e.g., TDS Pre-Login, TLS ClientHello, HTTP request) before
/// assuming the selected ZTA Connector blackholed the stream and retrying on a new stream.
pub const FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_millis(2500);

/// Maximum initial client bytes to buffer for stream-level replay when recovering from a
/// blackholed or prematurely closed ZTA Connector stream before any server bytes arrive.
pub const MAX_INITIAL_REPLAY_BYTES: usize = 16 * 1024;

/// Maximum number of fresh HTTP/2 stream retries when the initial stream produces 0 response bytes.
pub const MAX_INITIAL_STREAM_RETRIES: usize = 3;

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
    relay_bidirectional_with_retry_and_timeouts(
        a,
        b,
        "<tunnel>",
        || std::future::ready(Err(anyhow::anyhow!("stream retry disabled"))),
        FIRST_RESPONSE_TIMEOUT,
        half_close_timeout,
        0,
    )
    .await
}

/// Relays data bidirectionally between `a` (local client stream) and `b` (remote tunnel stream),
/// automatically recovering if the initial HTTP/2 tunnel stream hits a degraded ZTA Connector
/// that either closes the stream with 0 bytes (`EOF` / error) or blackholes the initial client
/// handshake payload without returning a single response byte within `FIRST_RESPONSE_TIMEOUT`.
pub async fn relay_bidirectional_with_retry<A, B, F, Fut>(
    a: &mut A,
    b: B,
    authority: &str,
    reopen: F,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<B>>,
{
    relay_bidirectional_with_retry_and_timeouts(
        a,
        b,
        authority,
        reopen,
        FIRST_RESPONSE_TIMEOUT,
        HALF_CLOSE_TIMEOUT,
        MAX_INITIAL_STREAM_RETRIES,
    )
    .await
}

pub async fn relay_bidirectional_with_retry_and_timeouts<A, B, F, Fut>(
    a: &mut A,
    mut b: B,
    authority: &str,
    mut reopen: F,
    first_response_timeout: Duration,
    half_close_timeout: Duration,
    max_retries: usize,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<B>>,
{
    enum RelayStep {
        Done(io::Result<(u64, u64)>),
        RetryInitialStream(&'static str),
    }

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

    let mut initial_client_buf: Vec<u8> = Vec::new();
    let mut replay_eligible = max_retries > 0;
    let mut retries_used = 0usize;

    let mut first_byte_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut half_close_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;

    loop {
        let step = futures::future::poll_fn(|cx| {
            // Direction 1: a -> b
            while !done_ab {
                if pos_ab < cap_ab {
                    match Pin::new(&mut b).poll_write(cx, &buf_ab[pos_ab..cap_ab]) {
                        Poll::Ready(Ok(0)) => {
                            if replay_eligible
                                && !done_ab
                                && total_ba == 0
                                && retries_used < max_retries
                            {
                                return Poll::Ready(RelayStep::RetryInitialStream(
                                    "returned write-zero before initial response",
                                ));
                            }
                            return Poll::Ready(RelayStep::Done(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into tunnel",
                            ))));
                        }
                        Poll::Ready(Ok(n)) => {
                            pos_ab += n;
                            total_ab += n as u64;
                            continue;
                        }
                        Poll::Ready(Err(e)) => {
                            if replay_eligible
                                && !done_ab
                                && total_ba == 0
                                && retries_used < max_retries
                            {
                                return Poll::Ready(RelayStep::RetryInitialStream(
                                    "failed on write before initial response",
                                ));
                            }
                            return Poll::Ready(RelayStep::Done(Err(e)));
                        }
                        Poll::Pending => {
                            let _ = Pin::new(&mut b).poll_flush(cx);
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
                            replay_eligible = false;
                            initial_client_buf.clear();
                            first_byte_sleep = None;
                            let _ = Pin::new(&mut b).poll_flush(cx);
                            let _ = Pin::new(&mut b).poll_shutdown(cx);
                            done_ab = true;
                            if half_close_sleep.is_none() && !done_ba {
                                half_close_sleep =
                                    Some(Box::pin(tokio::time::sleep(half_close_timeout)));
                            }
                        } else {
                            if replay_eligible {
                                if initial_client_buf.len() + n <= MAX_INITIAL_REPLAY_BYTES {
                                    initial_client_buf.extend_from_slice(&read_buf.filled()[..n]);
                                    if first_byte_sleep.is_none() && retries_used < max_retries {
                                        first_byte_sleep = Some(Box::pin(tokio::time::sleep(
                                            first_response_timeout,
                                        )));
                                    }
                                } else {
                                    replay_eligible = false;
                                    initial_client_buf.clear();
                                    first_byte_sleep = None;
                                }
                            }
                            cap_ab = n;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(RelayStep::Done(Err(e))),
                    Poll::Pending => {
                        let _ = Pin::new(&mut b).poll_flush(cx);
                        break;
                    }
                }
            }

            // Direction 2: b -> a
            while !done_ba {
                if pos_ba < cap_ba {
                    match Pin::new(&mut *a).poll_write(cx, &buf_ba[pos_ba..cap_ba]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(RelayStep::Done(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into local stream",
                            ))));
                        }
                        Poll::Ready(Ok(n)) => {
                            pos_ba += n;
                            total_ba += n as u64;
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(RelayStep::Done(Err(e))),
                        Poll::Pending => {
                            let _ = Pin::new(&mut *a).poll_flush(cx);
                            break;
                        }
                    }
                }

                pos_ba = 0;
                cap_ba = 0;
                let mut read_buf = ReadBuf::new(&mut buf_ba);
                match Pin::new(&mut b).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            if replay_eligible
                                && !done_ab
                                && total_ba == 0
                                && retries_used < max_retries
                            {
                                return Poll::Ready(RelayStep::RetryInitialStream(
                                    "closed with 0 bytes (EOF) before initial response",
                                ));
                            }
                            let _ = Pin::new(&mut *a).poll_flush(cx);
                            let _ = Pin::new(&mut *a).poll_shutdown(cx);
                            done_ba = true;
                            if half_close_sleep.is_none() && !done_ab {
                                half_close_sleep =
                                    Some(Box::pin(tokio::time::sleep(half_close_timeout)));
                            }
                        } else {
                            replay_eligible = false;
                            initial_client_buf.clear();
                            first_byte_sleep = None;
                            cap_ba = n;
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        if replay_eligible
                            && !done_ab
                            && total_ba == 0
                            && retries_used < max_retries
                        {
                            return Poll::Ready(RelayStep::RetryInitialStream(
                                "errored on read before initial response",
                            ));
                        }
                        return Poll::Ready(RelayStep::Done(Err(e)));
                    }
                    Poll::Pending => {
                        let _ = Pin::new(&mut *a).poll_flush(cx);
                        break;
                    }
                }
            }

            if done_ab && done_ba {
                return Poll::Ready(RelayStep::Done(Ok((total_ab, total_ba))));
            }

            if replay_eligible
                && !initial_client_buf.is_empty()
                && total_ba == 0
                && retries_used < max_retries
            {
                if let Some(ref mut sleep) = first_byte_sleep {
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(RelayStep::RetryInitialStream(
                            "timed out waiting for initial response byte",
                        ));
                    }
                }
            }

            if let Some(ref mut sleep) = half_close_sleep {
                if sleep.as_mut().poll(cx).is_ready() {
                    if !done_ab {
                        let _ = Pin::new(&mut b).poll_shutdown(cx);
                    }
                    if !done_ba {
                        let _ = Pin::new(&mut *a).poll_shutdown(cx);
                    }
                    return Poll::Ready(RelayStep::Done(Ok((total_ab, total_ba))));
                }
            }

            Poll::Pending
        })
        .await;

        match step {
            RelayStep::Done(res) => return res,
            RelayStep::RetryInitialStream(reason) => {
                retries_used += 1;
                tracing::warn!(
                    "Tunnel stream to {} {} (retry {}/{}); opening fresh H2 stream and replaying {} client bytes",
                    authority,
                    reason,
                    retries_used,
                    max_retries,
                    initial_client_buf.len()
                );
                drop(b);
                match reopen().await {
                    Ok(new_b) => {
                        b = new_b;
                        let len = initial_client_buf.len();
                        if len > 0 {
                            buf_ab[..len].copy_from_slice(&initial_client_buf);
                        }
                        pos_ab = 0;
                        cap_ab = len;
                        total_ab = 0;
                        first_byte_sleep =
                            if !initial_client_buf.is_empty() && retries_used < max_retries {
                                Some(Box::pin(tokio::time::sleep(first_response_timeout)))
                            } else {
                                None
                            };
                    }
                    Err(e) => {
                        let _ = a.shutdown().await;
                        return Err(io::Error::other(e.to_string()));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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

    #[tokio::test]
    async fn test_relay_bidirectional_with_retry_recovers_from_premature_eof() {
        let (mut app_side, mut relay_local) = tokio::io::duplex(1024);
        let (dead_tunnel_client, dead_tunnel_server) = tokio::io::duplex(1024);

        // First stream closes immediately with 0 bytes (simulating degraded ZTA Connector EOF)
        drop(dead_tunnel_server);

        let app_task = tokio::spawn(async move {
            // Simulate TDS Pre-Login request
            app_side.write_all(b"TDS_PRELOGIN_47B").await.unwrap();
            let mut resp = vec![0u8; 64];
            let n = app_side.read(&mut resp).await.unwrap();
            app_side.shutdown().await.unwrap();
            resp.truncate(n);
            resp
        });

        let (ab, ba) = relay_bidirectional_with_retry_and_timeouts(
            &mut relay_local,
            dead_tunnel_client,
            "dwh-db-sqls.bank.lan:1433",
            || async {
                let (healthy_client, mut healthy_server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut req = [0u8; 64];
                    let n = healthy_server.read(&mut req).await.unwrap();
                    assert_eq!(&req[..n], b"TDS_PRELOGIN_47B");
                    healthy_server
                        .write_all(b"TDS_PRELOGIN_RESPONSE_43B")
                        .await
                        .unwrap();
                    let _ = healthy_server.shutdown().await;
                });
                Ok(healthy_client)
            },
            Duration::from_millis(50),
            Duration::from_millis(20),
            3,
        )
        .await
        .unwrap();

        let received = app_task.await.unwrap();
        assert_eq!(&received[..], b"TDS_PRELOGIN_RESPONSE_43B");
        assert_eq!(ab, b"TDS_PRELOGIN_47B".len() as u64);
        assert_eq!(ba, b"TDS_PRELOGIN_RESPONSE_43B".len() as u64);
    }

    #[tokio::test]
    async fn test_relay_bidirectional_with_retry_recovers_from_initial_blackhole_timeout() {
        let (mut app_side, mut relay_local) = tokio::io::duplex(1024);
        let (blackhole_tunnel_client, _blackhole_tunnel_server_kept_open) =
            tokio::io::duplex(1024);

        let app_task = tokio::spawn(async move {
            app_side.write_all(b"TDS_PRELOGIN_PACKET").await.unwrap();
            let mut resp = vec![0u8; 64];
            let n = app_side.read(&mut resp).await.unwrap();
            app_side.shutdown().await.unwrap();
            resp.truncate(n);
            resp
        });

        let (ab, ba) = relay_bidirectional_with_retry_and_timeouts(
            &mut relay_local,
            blackhole_tunnel_client,
            "dwh-db-sqls.bank.lan:1433",
            || async {
                let (healthy_client, mut healthy_server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut req = [0u8; 64];
                    let n = healthy_server.read(&mut req).await.unwrap();
                    assert_eq!(&req[..n], b"TDS_PRELOGIN_PACKET");
                    healthy_server.write_all(b"TDS_PRELOGIN_ACK").await.unwrap();
                    let _ = healthy_server.shutdown().await;
                });
                Ok(healthy_client)
            },
            Duration::from_millis(40),
            Duration::from_millis(20),
            3,
        )
        .await
        .unwrap();

        let received = app_task.await.unwrap();
        assert_eq!(&received[..], b"TDS_PRELOGIN_ACK");
        assert_eq!(ab, b"TDS_PRELOGIN_PACKET".len() as u64);
        assert_eq!(ba, b"TDS_PRELOGIN_ACK".len() as u64);
    }
}
