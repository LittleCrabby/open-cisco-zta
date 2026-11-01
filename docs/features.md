# Key Features & Capabilities

This document provides an exhaustive breakdown of the features and capabilities supported by **open-cisco-zta**.

---

## 🚀 Overview of Capabilities

### 1. Cross-Platform Userspace Data Plane

`open-cisco-zta` provides two distinct modes for data plane ingress:

#### Linux Full-System Mode (Virtual TUN Interface)
- **Virtual TUN Interface:** Allocates a virtual network interface (`ztna0`, configurable via `--tun-name`) with IP `100.64.0.1/32` (configurable via `--tun-ip`).
- **Userspace TCP/IP Stack (`netstack-smoltcp`):** Processes incoming raw IP packets entirely in userspace without requiring custom kernel modules, eBPF programs, or kernel drivers.
- **Transparent Routing:** All corporate applications (curl, browsers, SSH, database GUIs, Docker containers, Kubernetes tooling) route through the tunnel automatically without application-specific proxy configurations.
- **Graceful Lifecycle:** Automatically restores all kernel routes, DNS configurations, and interface states on termination (`SIGINT`, `SIGTERM`).

#### Windows & Linux Unprivileged Mode (Local SOCKS5h Proxy)
- **Zero-Privilege Execution:** Runs entirely under regular user permissions without requiring root, `sudo`, or Windows Administrator elevation.
- **Local Proxy Endpoint:** Starts a high-performance SOCKS5h proxy server on `127.0.0.1:1080` (configurable via `--socks-addr`).
- **Remote DNS Resolution:** Supports standard SOCKS5h (RFC 1928), delegating domain resolution to the internal Fake-IP engine.
- **Wide Client Support:** Easily consumed by web browsers (Firefox, Chrome, Edge), developer tools (`git`, `curl`), SSH clients (`ProxyCommand nc -X 5`), and system-wide proxifiers (Proxifier, Tun2Socks).

---

### 2. High-Performance HTTP/2 Multiplexing & RFC 9298 MASQUE

Unlike legacy VPNs that create separate point-to-point tunnels, Cisco Secure Access ZTNA tunnels application flows through cloud-native HTTP/2 proxies:

- **mTLS Connection Pooling:** Maintains a multiplexed connection pool to the assigned Cisco cloud proxy (`proxy-<org_id>.zpc.sse.cisco.com:443`).
- **TCP Stream Tunneling:** Tunnels TCP flows using standard HTTP/2 `CONNECT` streams.
- **UDP Datagram Tunneling (MASQUE):** Tunnels UDP flows (e.g., Kerberos KDC on port 88, internal NTP/SNMP) using Extended `CONNECT` (`CONNECT-UDP`) per RFC 8441 and RFC 9298 MASQUE, packaging datagrams in RFC 9297 `DATAGRAM` capsules.
- **Active Keepalive:** Runs a background 30-second HTTP/2 `PING` keepalive task to maintain persistent connection health and prevent NAT timeout drops.
- **Optimized Window Sizes:** Configured with elevated initial stream and connection windows (`1 MiB` stream / `4 MiB` connection) and instantaneous capacity release (`flow_control().release_capacity()`) on frame consumption to eliminate flow stalls on high-throughput transfers.
- **Flow Posture Injection:** Enforces Cisco cloud security requirements by injecting `x-acidex-*` posture headers into each established stream.

---

### 3. End-to-End OS Posture Spoofing (`--os-profile`)

Enterprise posture rules often restrict access to specific operating systems (for example, requiring an approved corporate Linux build or Windows 11 installation). `open-cisco-zta` provides built-in OS posture spoofing:

- **Supported Profiles:**
  - `auto`: Uses the native host OS information.
  - `linux`: Emulates an authorized Ubuntu 22.04 LTS x86_64 workstation with modern kernel metadata.
  - `windows`: Emulates an enterprise Windows 11 Enterprise installation (`10.0.22631`).
- **Protocol Consistency:** Posture attributes are consistently applied across all stages:
  1. **Device Enrollment:** Hardware and OS identity exchanged during DHA registration (`register_dha`).
  2. **ConfigSync:** Attached to mTLS policy synchronization requests.
  3. **Data Plane:** Formatted into `x-acidex-*` headers on every HTTP/2 tunnel stream.
- **CLI Flags:** Controlled via `--os-profile <profile>` (with alias `--spoof-os <profile>`).

---

### 4. Embedded Fake-IP DNS Engine (`198.18.0.0/15`)

Traditional DNS queries for internal enterprise domains often fail or leak when sent to public DNS servers. The embedded Fake-IP DNS engine resolves this cleanly:

- **Synthetic IPv4 Space:** Allocates addresses dynamically from the benchmarking subnet `198.18.0.0/15` (`198.18.0.1` – `198.19.255.254`).
- **Instant Response Time:** Responds to corporate `A` record queries locally within milliseconds, avoiding cloud DNS roundtrip delays.
- **Strict DNS Isolation & Privacy:**
  - Queries matching corporate domains (`RouteMatcher`) are resolved internally.
  - Queries for non-A records (`AAAA`, `HTTPS` Type 65, `TXT`, etc.) on corporate domains immediately receive an empty `NOERROR` (NODATA) response. This eliminates latency caused by IPv6 timeout fallbacks and prevents corporate hostname leakage.
  - Non-corporate domains are transparently forwarded to the upstream resolver (`1.1.1.1:53` by default).
- **EDNS0 Mirroring:** Request EDNS0 extensions are preserved in responses (`set_dnssec_ok(false)`) to ensure full compatibility with modern resolvers like `systemd-resolved`.

---

### 5. Automated System Route & Split-DNS Management (Linux)

- **Kernel Routing:** Automatically binds routes for `198.18.0.0/15` and all policy-defined corporate CIDRs through the TUN interface.
- **`systemd-resolved` Split-DNS:**
  - Registers the TUN interface with `systemd-resolved` via `resolvectl dns`.
  - Configures routing domains (`~<domain>`) so only relevant internal corporate queries are dispatched to the client's internal DNS resolver.
  - Automatically deduplicates and prunes redundant subdomains to keep routing tables clean.
- **Firewall Integration:** Detects active `firewalld` daemons and automatically enrolls the TUN interface in the `trusted` zone.

---

### 6. Dynamic Policy Synchronization (`ConfigSync`)

- **Cloud Policy Updates:** Regularly fetches authorized corporate CIDR subnets, wildcard FQDN routing rules, and proxy servers from `/.well-known/zta-config/cisco/v2`.
- **HTTP/1.1 mTLS Transport:** Connects using mutual TLS authentication with HTTP/1.1.
- **Bandwidth Efficiency:** Employs HTTP ETag headers (`If-None-Match`), processing rule updates only when changes have occurred (`304 Not Modified`).
- **On-Demand Sync:** Users can manually trigger a policy sync at any time via the `sync` subcommand.

---

### 7. Standalone Enrollment & Custom ACME Certificate Lifecycle

- **Browser SSO Integration:** Launches the desktop browser (Edge, Chrome, Brave) to complete corporate SSO and MFA.
- **Automated DevTools Cookie Capture:** Captures the authenticated `elb-sso-jwt` cookie via Chrome DevTools Protocol over WebSockets, with graceful fallback to manual token entry if browser automation is unavailable.
- **Umbrella Device Registration:** Registers the endpoint with Cisco Umbrella APIs using RFC 9449 DPoP proofs.
- **DHA Posture Registration:** Performs hardware posture exchange with Cisco DHA endpoints.
- **Custom ACME v2 Issuance:** Interacts with Cisco's custom ACME CA (`prod.acme.sse.cisco.com`), answering `ztna-jwt` challenges and ordering certificates using `ZtnaUriList` identifiers to obtain an official intermediate CA-signed client certificate.

---

### 8. Built-in Safety & Conflict Checks

- **Sudo Enrollment Guard:** Disallows accidentally running `open-cisco-zta enroll` under `sudo` to protect against browser session permission corruption and root-owned config directories (`--allow-root` override available for headless environments).
- **TUN Privilege Verification:** Ensures proper privileges are present before attempting kernel TUN creation, suggesting `sudo` or `--proxy-only`.
- **Cisco Agent Conflict Detection:** Checks if official Cisco Secure Client daemons (`csc_zta_agent`, `acsockd`, `vpnagentd`) are actively running and warns the user to avoid network conflicts (`-f` / `--force` override available).

---

### 9. Non-Blocking Update Notifications

- Automatically checks GitHub Releases for new updates in the background.
- Employs a 24-hour disk cache (`.update_cache.json`) to prevent repeated lookups.
- Inspects GitHub redirect endpoints to bypass API rate limits.
- Never blocks or delays execution of CLI commands.
- Can be disabled at any time with `OPEN_CISCO_ZTA_NO_UPDATE_CHECK=1` or `CI=1`.
