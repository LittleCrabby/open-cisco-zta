use crate::dataplane::mux::Http2MuxTransport;
use crate::dataplane::router::RouteMatcher;
use crate::net::fakeip::{DnsServer, FakeIpPool};
use anyhow::{Context, Result};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use futures::{SinkExt, StreamExt};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use netstack_smoltcp::StackBuilder;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::sync::Mutex;

pub struct TunDevice {
    name: String,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: i32,
    router: Arc<RouteMatcher>,
    fake_pool: FakeIpPool,
    mux: Arc<Http2MuxTransport>,
    upstream_dns: SocketAddr,
}

impl TunDevice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: i32,
        router: Arc<RouteMatcher>,
        fake_pool: FakeIpPool,
        mux: Arc<Http2MuxTransport>,
        upstream_dns: SocketAddr,
    ) -> Self {
        Self {
            name: name.to_string(),
            ip,
            netmask,
            mtu,
            router,
            fake_pool,
            mux,
            upstream_dns,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub async fn run(&self) -> Result<()> {
        let mut config = tun::Configuration::default();
        config
            .name(&self.name)
            .address(self.ip)
            .netmask(self.netmask)
            .mtu(self.mtu)
            .up();

        let tun_dev = tun::create_as_async(&config)
            .with_context(|| format!("Failed to create TUN interface '{}' (requires root/CAP_NET_ADMIN)", self.name))?;

        tracing::info!(
            "TUN interface '{}' created with IP {}/{} MTU {}",
            self.name,
            self.ip,
            self.netmask,
            self.mtu
        );

        let (stack, runner, udp_sock, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .mtu(self.mtu as usize)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build netstack: {:?}", e))?;

        if let Some(r) = runner {
            tokio::spawn(async move {
                if let Err(e) = r.await {
                    tracing::error!("Netstack TCP runner error: {:?}", e);
                }
            });
        }

        let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_dev);
        let (mut stack_sink, mut stack_stream) = stack.split();

        // Task 1: TUN Reader -> Stack Sink (ingress into userspace netstack)
        let mtu = self.mtu as usize;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let packet = buf[..n].to_vec();
                        if let Err(e) = stack_sink.send(packet).await {
                            tracing::debug!("Stack sink send error: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("TUN read error: {:?}", e);
                        break;
                    }
                }
            }
        });

        // Task 2: Stack Stream -> TUN Writer (egress packets from userspace netstack to OS)
        tokio::spawn(async move {
            while let Some(packet_res) = stack_stream.next().await {
                match packet_res {
                    Ok(packet) => {
                        if let Err(e) = tun_writer.write_all(&packet).await {
                            tracing::error!("TUN write error: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Stack stream packet error: {:?}", e);
                    }
                }
            }
        });

        // Task 3: Accept UDP packets from netstack (DNS on port 53 + CONNECT-UDP tunneling for corporate UDP flows)
        if let Some(udp) = udp_sock {
            let (mut udp_read, mut udp_write) = udp.split();
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(1024);

            tokio::spawn(async move {
                while let Some((data, local, remote)) = rx.recv().await {
                    // Send response back: remote becomes src, local becomes dst
                    if let Err(e) = udp_write.send((data, remote, local)).await {
                        tracing::debug!("UDP netstack write error: {:?}", e);
                    }
                }
            });

            let router = Arc::clone(&self.router);
            let fake_pool = self.fake_pool.clone();
            let mux = Arc::clone(&self.mux);
            let upstream = self.upstream_dns;
            type UdpFlowKey = (SocketAddr, SocketAddr);
            let udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, tokio::sync::mpsc::Sender<Vec<u8>>>>> =
                Arc::new(Mutex::new(HashMap::new()));

            tokio::spawn(async move {
                while let Some((data, local, remote)) = udp_read.next().await {
                    if remote.port() == 53 {
                        let router = Arc::clone(&router);
                        let fake_pool = fake_pool.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match DnsServer::handle_query(&data, router, fake_pool, upstream).await {
                                Ok(resp_bytes) => {
                                    let _ = tx.send((resp_bytes, local, remote)).await;
                                }
                                Err(e) => {
                                    tracing::debug!("Netstack DNS UDP error: {:?}", e);
                                }
                            }
                        });
                    } else {
                        let flow_key = (local, remote);
                        {
                            let mut map = udp_sessions.lock().await;
                            if let Some(flow_tx) = map.get(&flow_key) {
                                if flow_tx.try_send(data.clone()).is_ok() {
                                    continue;
                                }
                                map.remove(&flow_key);
                            }
                        }

                        let (flow_tx, mut flow_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
                        let _ = flow_tx.try_send(data);
                        {
                            let mut map = udp_sessions.lock().await;
                            map.insert(flow_key, flow_tx);
                        }

                        let fake_pool = fake_pool.clone();
                        let mux = Arc::clone(&mux);
                        let router = Arc::clone(&router);
                        let tx = tx.clone();
                        let udp_sessions_cleanup = Arc::clone(&udp_sessions);

                        tokio::spawn(async move {
                            let dst_ip = remote.ip();
                            let dst_port = remote.port();

                            let authority = match dst_ip {
                                IpAddr::V4(v4) if FakeIpPool::is_fake_ip(v4) => {
                                    if let Some(domain) = fake_pool.lookup_domain(v4).await {
                                        format!("{}:{}", domain, dst_port)
                                    } else {
                                        tracing::warn!(
                                            "TUN UDP packet from {} to unallocated Fake-IP {}:{}; dropping",
                                            local,
                                            v4,
                                            dst_port
                                        );
                                        udp_sessions_cleanup.lock().await.remove(&flow_key);
                                        return;
                                    }
                                }
                                _ => {
                                    if !router.matches_ip(dst_ip) {
                                        tracing::debug!(
                                            "TUN UDP destination {}:{} is excluded by CIDR policy; dropping",
                                            dst_ip,
                                            dst_port
                                        );
                                        udp_sessions_cleanup.lock().await.remove(&flow_key);
                                        return;
                                    }
                                    format!("{}:{}", dst_ip, dst_port)
                                }
                            };

                            tracing::info!(
                                "TUN UDP flow from {} to authority {} (CONNECT-UDP)",
                                local,
                                authority
                            );

                            match mux.open_udp_tunnel(&authority, Some(local)).await {
                                Ok(mut udp_tunnel) => {
                                    let idle_timeout = Duration::from_secs(60);
                                    loop {
                                        tokio::select! {
                                            pkt_opt = flow_rx.recv() => {
                                                match pkt_opt {
                                                    Some(pkt) => {
                                                        if let Err(e) = udp_tunnel.send_datagram(&pkt).await {
                                                            tracing::debug!(
                                                                "UDP tunnel write error for {}: {:?}",
                                                                authority,
                                                                e
                                                            );
                                                            break;
                                                        }
                                                    }
                                                    None => break,
                                                }
                                            }
                                            resp_res = udp_tunnel.recv_datagram() => {
                                                match resp_res {
                                                    Ok(Some(resp_bytes)) => {
                                                        if tx.send((resp_bytes.to_vec(), local, remote)).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Ok(None) => {
                                                        tracing::debug!("UDP tunnel EOF for {}", authority);
                                                        break;
                                                    }
                                                    Err(e) => {
                                                        tracing::debug!(
                                                            "UDP tunnel read error for {}: {:?}",
                                                            authority,
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                            }
                                            _ = tokio::time::sleep(idle_timeout) => {
                                                tracing::debug!(
                                                    "Closing idle UDP tunnel from {} to {}",
                                                    local,
                                                    authority
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    let _ = udp_tunnel.shutdown().await;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to open UDP tunnel (CONNECT-UDP) to {}: {:?}",
                                        authority,
                                        e
                                    );
                                }
                            }

                            udp_sessions_cleanup.lock().await.remove(&flow_key);
                        });
                    }
                }
            });
        }

        // Task 4: Accept TCP connections from netstack
        if let Some(mut listener) = tcp_listener {
            let fake_pool = self.fake_pool.clone();
            let mux = Arc::clone(&self.mux);
            let router = Arc::clone(&self.router);
            let upstream = self.upstream_dns;

            tokio::spawn(async move {
                while let Some((mut stream, local_addr, peer_addr)) = listener.next().await {
                    // Check if this is a TCP DNS request to port 53
                    if peer_addr.port() == 53 {
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
                            if let Ok(resp_bytes) = DnsServer::handle_query(&req_buf, router, fake_pool, upstream).await {
                                let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                                let _ = stream.write_all(&resp_len).await;
                                let _ = stream.write_all(&resp_bytes).await;
                            }
                        });
                        continue;
                    }

                    // Regular TCP tunnel to authority
                    let fake_pool = fake_pool.clone();
                    let mux = Arc::clone(&mux);
                    let router = Arc::clone(&router);

                    tokio::spawn(async move {
                        let dst_ip = peer_addr.ip();
                        let dst_port = peer_addr.port();

                        let authority = match dst_ip {
                            IpAddr::V4(v4) if FakeIpPool::is_fake_ip(v4) => {
                                if let Some(domain) = fake_pool.lookup_domain(v4).await {
                                    format!("{}:{}", domain, dst_port)
                                } else {
                                    tracing::warn!(
                                        "TUN TCP connection from {} to unallocated Fake-IP {}:{}; dropping",
                                        local_addr,
                                        v4,
                                        dst_port
                                    );
                                    return;
                                }
                            }
                            _ => {
                                if !router.matches_ip(dst_ip) {
                                    tracing::debug!(
                                        "TUN TCP destination {}:{} is excluded by CIDR policy; dropping",
                                        dst_ip,
                                        dst_port
                                    );
                                    return;
                                }
                                format!("{}:{}", dst_ip, dst_port)
                            }
                        };

                        tracing::info!(
                            "TUN TCP connection from {} to authority {}",
                            local_addr,
                            authority
                        );

                        match mux.open_tcp_tunnel(&authority, Some(local_addr)).await {
                            Ok(mut tunnel) => {
                                let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
                            }
                            Err(e) => {
                                tracing::error!("Failed to tunnel TCP connection to {}: {:?}", authority, e);
                            }
                        }
                    });
                }
            });
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub async fn run(&self) -> Result<()> {
        anyhow::bail!(
            "Kernel TUN interface is supported on Linux and Windows. \
             On other platforms, please run with `--proxy-only` mode (SOCKS5h proxy)."
        );
    }
}
