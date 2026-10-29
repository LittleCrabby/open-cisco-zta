use crate::dataplane::mux::Http2MuxTransport;
use crate::dataplane::router::RouteMatcher;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Socks5Server {
    listen_addr: SocketAddr,
    router: Arc<RouteMatcher>,
    mux: Arc<Http2MuxTransport>,
}

impl Socks5Server {
    pub fn new(
        listen_addr: SocketAddr,
        router: Arc<RouteMatcher>,
        mux: Arc<Http2MuxTransport>,
    ) -> Self {
        Self {
            listen_addr,
            router,
            mux,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| format!("Failed to bind SOCKS5 listener on {}", self.listen_addr))?;

        tracing::info!("SOCKS5h server listening on {}", self.listen_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("Failed to accept SOCKS5 connection: {:?}", e);
                    continue;
                }
            };

            let router = Arc::clone(&self.router);
            let mux = Arc::clone(&self.mux);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, peer_addr, router, mux).await {
                    tracing::debug!("Connection from {} closed with error: {:?}", peer_addr, e);
                }
            });
        }
    }

    async fn handle_client(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<RouteMatcher>,
        mux: Arc<Http2MuxTransport>,
    ) -> Result<()> {
        // Peek or read initial byte to determine protocol: SOCKS5 (0x05) or HTTP CONNECT ('C' / 'P')
        let mut first_byte = [0u8; 1];
        stream.read_exact(&mut first_byte).await?;

        if first_byte[0] == 0x05 {
            // SOCKS5 handshake
            let mut nmethods_buf = [0u8; 1];
            stream.read_exact(&mut nmethods_buf).await?;
            let nmethods = nmethods_buf[0] as usize;
            let mut methods = vec![0u8; nmethods];
            stream.read_exact(&mut methods).await?;

            // We support NO AUTH (0x00)
            if !methods.contains(&0x00) {
                stream.write_all(&[0x05, 0xFF]).await?;
                bail!("Client does not support NO_AUTH");
            }
            stream.write_all(&[0x05, 0x00]).await?;

            // Read request
            let mut req_header = [0u8; 4];
            stream.read_exact(&mut req_header).await?;
            let version = req_header[0];
            let cmd = req_header[1];
            let atyp = req_header[3];

            if version != 0x05 {
                bail!("Unsupported SOCKS version: {}", version);
            }
            if cmd != 0x01 {
                // Only CONNECT is supported
                stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                bail!("Unsupported SOCKS5 command: {}", cmd);
            }

            let (target_host, target_ip, target_port) = match atyp {
                0x01 => {
                    // IPv4
                    let mut ip_buf = [0u8; 4];
                    stream.read_exact(&mut ip_buf).await?;
                    let ip = IpAddr::V4(Ipv4Addr::from(ip_buf));
                    let mut port_buf = [0u8; 2];
                    stream.read_exact(&mut port_buf).await?;
                    let port = u16::from_be_bytes(port_buf);
                    (ip.to_string(), Some(ip), port)
                }
                0x03 => {
                    // Domain name
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await?;
                    let len = len_buf[0] as usize;
                    let mut domain_buf = vec![0u8; len];
                    stream.read_exact(&mut domain_buf).await?;
                    let domain = String::from_utf8(domain_buf)
                        .map_err(|_| anyhow::anyhow!("Invalid domain utf8"))?;
                    let mut port_buf = [0u8; 2];
                    stream.read_exact(&mut port_buf).await?;
                    let port = u16::from_be_bytes(port_buf);
                    (domain, None, port)
                }
                0x04 => {
                    // IPv6
                    let mut ip_buf = [0u8; 16];
                    stream.read_exact(&mut ip_buf).await?;
                    let ip = IpAddr::V6(Ipv6Addr::from(ip_buf));
                    let mut port_buf = [0u8; 2];
                    stream.read_exact(&mut port_buf).await?;
                    let port = u16::from_be_bytes(port_buf);
                    (ip.to_string(), Some(ip), port)
                }
                other => {
                    stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                    bail!("Unsupported ATYP: {}", other);
                }
            };

            let authority = format!("{}:{}", target_host, target_port);
            let is_corporate = router.should_route(&target_host, target_ip);

            tracing::info!(
                "SOCKS5 request for {} (corporate: {}) from {}",
                authority,
                is_corporate,
                peer_addr
            );

            if is_corporate {
                match mux.open_tcp_tunnel(&authority, Some(peer_addr)).await {
                    Ok(mut tunnel) => {
                        // SOCKS5 Success response
                        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to open ZTNA tunnel for {}: {:?}", authority, e);
                        let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    }
                }
            } else {
                // Direct connection
                match TcpStream::connect(&authority).await {
                    Ok(mut direct) => {
                        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut direct).await;
                    }
                    Err(e) => {
                        tracing::warn!("Failed direct connect to {}: {:?}", authority, e);
                        let _ = stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    }
                }
            }
        } else {
            // Check if HTTP CONNECT or GET
            bail!("Only SOCKS5 is implemented on this port");
        }

        Ok(())
    }
}
