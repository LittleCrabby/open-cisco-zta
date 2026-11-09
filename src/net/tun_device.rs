use crate::dataplane::mux::Http2MuxTransport;
use crate::dataplane::router::RouteMatcher;
use crate::net::fakeip::{DnsServer, FakeIpPool};
use anyhow::{Context, Result};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use futures::{SinkExt, StreamExt};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use netstack_smoltcp::smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, UdpPacket,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use netstack_smoltcp::StackBuilder;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::collections::{BTreeMap, HashMap};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::time::{Duration, Instant};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::sync::Mutex;

#[cfg(any(target_os = "linux", target_os = "windows"))]
const IPV4_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "windows"))]
const MAX_IPV4_REASSEMBLY_ENTRIES: usize = 64;
#[cfg(any(target_os = "linux", target_os = "windows"))]
const MAX_UDP_WIRE_LEN: usize = u16::MAX as usize;
#[cfg(any(target_os = "linux", target_os = "windows"))]
static EGRESS_IPV4_IDENT: AtomicU16 = AtomicU16::new(1);

#[cfg(any(target_os = "linux", target_os = "windows"))]
type ReassemblyKey = (Ipv4Addr, Ipv4Addr, u16);

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct ReassemblyEntry {
    created_at: Instant,
    total_len: Option<usize>,
    fragments: BTreeMap<usize, Vec<u8>>,
}

/// Bounded IPv4 fragment reassembler for UDP datagrams exceeding the TUN MTU.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) struct Ipv4UdpReassembler {
    entries: HashMap<ReassemblyKey, ReassemblyEntry>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Ipv4UdpReassembler {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub(crate) fn insert_fragment(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ident: u16,
        frag_offset: usize,
        more_frags: bool,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.created_at) < IPV4_REASSEMBLY_TIMEOUT);

        if payload.is_empty() {
            return None;
        }
        let end_offset = frag_offset.checked_add(payload.len())?;
        if end_offset > MAX_UDP_WIRE_LEN {
            self.entries.remove(&(src_ip, dst_ip, ident));
            return None;
        }

        let key = (src_ip, dst_ip, ident);
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_IPV4_REASSEMBLY_ENTRIES {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }

        let entry = self.entries.entry(key).or_insert_with(|| ReassemblyEntry {
            created_at: now,
            total_len: None,
            fragments: BTreeMap::new(),
        });

        if !more_frags {
            if let Some(existing_total) = entry.total_len {
                if existing_total != end_offset {
                    self.entries.remove(&key);
                    return None;
                }
            }
            entry.total_len = Some(end_offset);
        } else if let Some(existing_total) = entry.total_len {
            if end_offset >= existing_total {
                self.entries.remove(&key);
                return None;
            }
        }

        entry.fragments.insert(frag_offset, payload.to_vec());

        let total_len = entry.total_len?;
        let mut expected_offset = 0usize;
        for (&offset, chunk) in &entry.fragments {
            if offset != expected_offset {
                return None;
            }
            expected_offset += chunk.len();
        }
        if expected_offset != total_len {
            return None;
        }

        let completed = self.entries.remove(&key)?;
        let mut reassembled = Vec::with_capacity(total_len);
        for chunk in completed.fragments.into_values() {
            reassembled.extend_from_slice(&chunk);
        }
        Some(reassembled)
    }
}

/// Returns `true` if `frame` is a valid IPv4 or IPv6 packet with next_header == UDP.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn is_udp_ip_packet(frame: &[u8]) -> bool {
    match IpVersion::of_packet(frame) {
        Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(frame)
            .map(|p| p.next_header() == IpProtocol::Udp)
            .unwrap_or(false),
        Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(frame)
            .map(|p| p.next_header() == IpProtocol::Udp)
            .unwrap_or(false),
        _ => false,
    }
}

/// Parses an ingress IPv4/IPv6 UDP frame (reassembling IPv4 fragments if needed).
/// Malformed or truncated packets are logged and ignored (`None`), never terminating the stream.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn parse_udp_ip_packet(
    frame: &[u8],
    reassembler: &mut Ipv4UdpReassembler,
) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
    match IpVersion::of_packet(frame) {
        Ok(IpVersion::Ipv4) => {
            let ipv4 = Ipv4Packet::new_checked(frame).ok()?;
            if ipv4.next_header() != IpProtocol::Udp {
                return None;
            }
            let src_ip = ipv4.src_addr();
            let dst_ip = ipv4.dst_addr();

            if !ipv4.more_frags() && ipv4.frag_offset() == 0 {
                parse_udp_datagram(
                    ipv4.payload(),
                    IpAddr::V4(src_ip),
                    IpAddr::V4(dst_ip),
                )
            } else {
                let reassembled = reassembler.insert_fragment(
                    src_ip,
                    dst_ip,
                    ipv4.ident(),
                    ipv4.frag_offset() as usize,
                    ipv4.more_frags(),
                    ipv4.payload(),
                )?;
                parse_udp_datagram(&reassembled, IpAddr::V4(src_ip), IpAddr::V4(dst_ip))
            }
        }
        Ok(IpVersion::Ipv6) => {
            let ipv6 = Ipv6Packet::new_checked(frame).ok()?;
            if ipv6.next_header() != IpProtocol::Udp {
                return None;
            }
            let src_ip = ipv6.src_addr();
            let dst_ip = ipv6.dst_addr();
            parse_udp_datagram(
                ipv6.payload(),
                IpAddr::V6(src_ip),
                IpAddr::V6(dst_ip),
            )
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_udp_datagram(
    udp_bytes: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
    let udp = match UdpPacket::new_checked(udp_bytes) {
        Ok(pkt) => pkt,
        Err(e) => {
            tracing::debug!(
                "Ignoring malformed UDP packet from {} to {} ({} bytes): {:?}",
                src_ip,
                dst_ip,
                udp_bytes.len(),
                e
            );
            return None;
        }
    };
    let udp_len = udp.len() as usize;
    if udp_len < 8 {
        return None;
    }
    let payload_len = udp_len - 8;
    let payload_slice = udp.payload();
    if payload_slice.len() < payload_len {
        return None;
    }
    let src_addr = SocketAddr::new(src_ip, udp.src_port());
    let dst_addr = SocketAddr::new(dst_ip, udp.dst_port());
    Some((
        payload_slice[..payload_len].to_vec(),
        src_addr,
        dst_addr,
    ))
}

/// Builds one or more IPv4/IPv6 packets encapsulating a UDP datagram from `src` to `dst`,
/// fragmenting IPv4 packets if the UDP datagram exceeds `mtu`.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn build_udp_ip_packets(
    payload: &[u8],
    src: SocketAddr,
    dst: SocketAddr,
    mtu: usize,
) -> Vec<Vec<u8>> {
    let udp_len = 8usize.saturating_add(payload.len());
    if udp_len > MAX_UDP_WIRE_LEN {
        tracing::warn!(
            "Dropping oversized UDP response from {} to {} ({} bytes > 65535)",
            src,
            dst,
            udp_len
        );
        return Vec::new();
    }

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let smol_src = src_v4;
            let smol_dst = dst_v4;

            let mut udp_buf = vec![0u8; udp_len];
            {
                let mut udp = UdpPacket::new_unchecked(&mut udp_buf);
                udp.set_src_port(src.port());
                udp.set_dst_port(dst.port());
                udp.set_len(udp_len as u16);
                udp.payload_mut()[..payload.len()].copy_from_slice(payload);
                udp.fill_checksum(&IpAddress::Ipv4(smol_src), &IpAddress::Ipv4(smol_dst));
            }

            let ident = EGRESS_IPV4_IDENT.fetch_add(1, Ordering::Relaxed);
            let max_ip_payload = mtu.saturating_sub(20);
            if udp_len <= max_ip_payload || max_ip_payload < 8 {
                let total_len = 20 + udp_len;
                if total_len > u16::MAX as usize {
                    return Vec::new();
                }
                let mut ip_buf = vec![0u8; total_len];
                {
                    let mut ip = Ipv4Packet::new_unchecked(&mut ip_buf);
                    ip.set_version(4);
                    ip.set_header_len(20);
                    ip.set_dscp(0);
                    ip.set_ecn(0);
                    ip.set_total_len(total_len as u16);
                    ip.set_ident(ident);
                    ip.clear_flags();
                    ip.set_more_frags(false);
                    ip.set_frag_offset(0);
                    ip.set_hop_limit(64);
                    ip.set_next_header(IpProtocol::Udp);
                    ip.set_src_addr(smol_src);
                    ip.set_dst_addr(smol_dst);
                    ip.payload_mut()[..udp_len].copy_from_slice(&udp_buf);
                    ip.fill_checksum();
                }
                vec![ip_buf]
            } else {
                let frag_chunk_len = max_ip_payload & !7;
                let mut packets = Vec::new();
                let mut offset = 0usize;
                while offset < udp_len {
                    let remaining = udp_len - offset;
                    let is_last = remaining <= max_ip_payload;
                    let chunk_len = if is_last { remaining } else { frag_chunk_len };
                    let total_len = 20 + chunk_len;
                    let mut ip_buf = vec![0u8; total_len];
                    {
                        let mut ip = Ipv4Packet::new_unchecked(&mut ip_buf);
                        ip.set_version(4);
                        ip.set_header_len(20);
                        ip.set_dscp(0);
                        ip.set_ecn(0);
                        ip.set_total_len(total_len as u16);
                        ip.set_ident(ident);
                        ip.clear_flags();
                        ip.set_more_frags(!is_last);
                        ip.set_frag_offset(offset as u16);
                        ip.set_hop_limit(64);
                        ip.set_next_header(IpProtocol::Udp);
                        ip.set_src_addr(smol_src);
                        ip.set_dst_addr(smol_dst);
                        ip.payload_mut()[..chunk_len]
                            .copy_from_slice(&udp_buf[offset..offset + chunk_len]);
                        ip.fill_checksum();
                    }
                    packets.push(ip_buf);
                    offset += chunk_len;
                }
                packets
            }
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let smol_src = src_v6;
            let smol_dst = dst_v6;
            let total_len = 40 + udp_len;
            let mut ip_buf = vec![0u8; total_len];
            {
                let mut ip = Ipv6Packet::new_unchecked(&mut ip_buf);
                ip.set_version(6);
                ip.set_traffic_class(0);
                ip.set_flow_label(0);
                ip.set_payload_len(udp_len as u16);
                ip.set_next_header(IpProtocol::Udp);
                ip.set_hop_limit(64);
                ip.set_src_addr(smol_src);
                ip.set_dst_addr(smol_dst);

                let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
                udp.set_src_port(src.port());
                udp.set_dst_port(dst.port());
                udp.set_len(udp_len as u16);
                udp.payload_mut()[..payload.len()].copy_from_slice(payload);
                udp.fill_checksum(&IpAddress::Ipv6(smol_src), &IpAddress::Ipv6(smol_dst));
            }
            vec![ip_buf]
        }
        _ => Vec::new(),
    }
}

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

        let (stack, runner, _udp_sock, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
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

        let (udp_ingress_tx, mut udp_ingress_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let (udp_egress_tx, mut udp_egress_rx) =
            tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(1024);

        // Task 1: TUN Reader -> UDP Ingress Channel or Netstack Sink
        let mtu = self.mtu as usize;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let packet = buf[..n].to_vec();
                        if is_udp_ip_packet(&packet) {
                            if udp_ingress_tx.send(packet).await.is_err() {
                                tracing::error!("UDP ingress channel closed");
                                break;
                            }
                        } else if let Err(e) = stack_sink.send(packet).await {
                            if e.kind() == std::io::ErrorKind::BrokenPipe {
                                tracing::error!("Netstack sink closed: {:?}", e);
                                break;
                            }
                            tracing::debug!("Ignoring non-fatal netstack sink error: {:?}", e);
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::Interrupted
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        continue;
                    }
                    Err(e) => {
                        tracing::error!("TUN read error: {:?}", e);
                        break;
                    }
                }
            }
        });

        // Task 2: Netstack Stream & UDP Egress -> TUN Writer (egress packets to OS)
        let egress_mtu = self.mtu as usize;
        tokio::spawn(async move {
            let mut stack_open = true;
            let mut udp_open = true;
            while stack_open || udp_open {
                tokio::select! {
                    packet_opt = stack_stream.next(), if stack_open => {
                        match packet_opt {
                            Some(Ok(packet)) => {
                                if let Err(e) = tun_writer.write_all(&packet).await {
                                    if e.kind() == std::io::ErrorKind::InvalidInput {
                                        tracing::warn!(
                                            "Dropping egress TCP/ICMP packet rejected by TUN ({} bytes): {:?}",
                                            packet.len(),
                                            e
                                        );
                                        continue;
                                    }
                                    tracing::error!("TUN write error: {:?}", e);
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                tracing::debug!("Stack stream packet error: {:?}", e);
                            }
                            None => {
                                stack_open = false;
                            }
                        }
                    }
                    udp_opt = udp_egress_rx.recv(), if udp_open => {
                        match udp_opt {
                            Some((data, local, remote)) => {
                                // Send response back: remote becomes src, local becomes dst
                                for packet in build_udp_ip_packets(&data, remote, local, egress_mtu) {
                                    if let Err(e) = tun_writer.write_all(&packet).await {
                                        if e.kind() == std::io::ErrorKind::InvalidInput {
                                            tracing::warn!(
                                                "Dropping egress UDP packet rejected by TUN ({} bytes): {:?}",
                                                packet.len(),
                                                e
                                            );
                                            continue;
                                        }
                                        tracing::error!("TUN write error on UDP egress: {:?}", e);
                                        return;
                                    }
                                }
                            }
                            None => {
                                udp_open = false;
                            }
                        }
                    }
                }
            }
        });

        // Task 3: Process UDP packets (DNS on port 53 + CONNECT-UDP tunneling for corporate UDP flows)
        {
            let router = Arc::clone(&self.router);
            let fake_pool = self.fake_pool.clone();
            let mux = Arc::clone(&self.mux);
            let upstream = self.upstream_dns;
            let tx = udp_egress_tx;
            type UdpFlowKey = (SocketAddr, SocketAddr);
            let udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, tokio::sync::mpsc::Sender<Vec<u8>>>>> =
                Arc::new(Mutex::new(HashMap::new()));

            tokio::spawn(async move {
                let mut reassembler = Ipv4UdpReassembler::new();
                while let Some(raw_frame) = udp_ingress_rx.recv().await {
                    let Some((data, local, remote)) =
                        parse_udp_ip_packet(&raw_frame, &mut reassembler)
                    else {
                        continue;
                    };
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
                                let _ = crate::dataplane::mux::relay_bidirectional(
                                    &mut stream,
                                    &mut tunnel,
                                )
                                .await;
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

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn test_unfragmented_udp_build_and_parse() {
        let src: SocketAddr = "100.64.0.1:53124".parse().unwrap();
        let dst: SocketAddr = "198.18.0.14:53".parse().unwrap();
        let payload = b"hello corporate dns".to_vec();

        let packets = build_udp_ip_packets(&payload, src, dst, 1400);
        assert_eq!(packets.len(), 1);
        assert!(is_udp_ip_packet(&packets[0]));

        let mut reassembler = Ipv4UdpReassembler::new();
        let (parsed_payload, parsed_src, parsed_dst) =
            parse_udp_ip_packet(&packets[0], &mut reassembler).expect("should parse single UDP packet");
        assert_eq!(parsed_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_fragmented_ipv4_udp_reassembly_and_survival_on_corrupted_packet() {
        // Reproduce the exact 2874-byte UDP datagram (2866-byte GZIP GelF payload + 8-byte UDP header)
        // to 198.18.0.14:12459 across MTU 1400 (3 IPv4 fragments).
        let src: SocketAddr = "100.64.0.1:36290".parse().unwrap();
        let dst: SocketAddr = "198.18.0.14:12459".parse().unwrap();
        let mut payload = vec![0u8; 2866];
        payload[..4].copy_from_slice(&[31, 139, 8, 0]); // GZIP magic
        for (i, b) in payload[4..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let fragments = build_udp_ip_packets(&payload, src, dst, 1400);
        assert_eq!(fragments.len(), 3);
        for frag in &fragments {
            assert!(frag.len() <= 1400);
            assert!(is_udp_ip_packet(frag));
        }

        let mut reassembler = Ipv4UdpReassembler::new();
        // Fragment 1 alone must NOT return a completed packet or kill the parser
        assert!(parse_udp_ip_packet(&fragments[0], &mut reassembler).is_none());

        // Injecting a truncated/corrupted unfragmented UDP packet in the middle must return None
        // and leave the reassembler intact for subsequent packets.
        let mut corrupted = fragments[0].clone();
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut corrupted);
            ip.set_more_frags(false);
            ip.set_frag_offset(0);
            ip.fill_checksum();
        }
        assert!(parse_udp_ip_packet(&corrupted, &mut reassembler).is_none());

        // Deliver Fragment 3 out-of-order before Fragment 2
        assert!(parse_udp_ip_packet(&fragments[2], &mut reassembler).is_none());

        // Deliver Fragment 2 -> completes reassembly of the 2866-byte UDP payload!
        let (reassembled_payload, parsed_src, parsed_dst) =
            parse_udp_ip_packet(&fragments[1], &mut reassembler)
                .expect("should reassemble 3 IPv4 UDP fragments");
        assert_eq!(reassembled_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }
}
