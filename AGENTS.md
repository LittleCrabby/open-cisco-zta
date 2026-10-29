# AGENTS.md — Developer & AI Agent Guidelines

This document outlines the critical protocol invariants, networking behaviors, cross-platform rules, and maintenance requirements for `open-cisco-zta`. Read this before modifying protocol, cryptographic, or networking code.

---

## 1. Cisco ZTNA Protocol & Cryptographic Invariants

Several components interact with Cisco Secure Access cloud endpoints (`*.ztna.sse.cisco.com`, `*.zpc.sse.cisco.com`, `devices.api.umbrella.com`, `prod.acme.sse.cisco.com`) that enforce non-standard extensions on top of standard RFCs. **Do not simplify or alter these behaviors without verifying against live Cisco endpoints:**

- **DPoP Proofs & Composite `Authorization` Headers (`src/crypto/dpop.rs`, `src/control/enroll.rs`):**
  - **Device Registration (`register_device`):** Requires a composite header `Authorization: DPOP <sso_jwt>, Bearer <sso_jwt>`. The `Dpop` header must contain a proof signed with ES256 (`typ: "dpop+jwt"`) that includes both `ath` (SHA-256 of `sso_jwt`) and `body_hash` (SHA-256 of the JSON request body).
  - **DHA Registration (`register_dha`):** Requires a composite header `Authorization: DPOP <sso_jwt>, DPOP <dr_jwt>`. The `Dpop` proof (`generate_dha_proof`) must include `elb_ath` (SHA-256 of `sso_jwt`), `dr_ath` (SHA-256 of `dr_jwt`), and `body_hash`.
  - Per RFC 9449, `htu` in DPoP claims must have query strings and fragments stripped.
- **Custom ACME v2 Certificate Issuance (`src/crypto/acme.rs`):**
  - **Order Identifier:** Cisco's ACME server requires a custom identifier type `"ZtnaUriList"`, where `value` is the base64url-encoded (no padding) JSON serialization of a deterministically sorted (`BTreeMap`) SAN URI map.
  - **Custom Challenge (`ztna-jwt`):** Authorization challenges use `type == "ztna-jwt"` and are answered with a `POST` payload of `{}` accompanied by `Authorization: DPoP <auth_jwt>` and `Dpop: <proof>` headers.
  - **Mandatory Headers:** All ACME requests must include `x-request-id` (UUID v4) and `x-zta-enrollment-id` (device/enrollment ID).
  - **CSR Subject & SANs:** The CSR `CommonName` must be `urn:cisco:sse:ztna:deviceid:<device_id>`, and all `san_map` entries (`urn:cisco:sse:...`) must be encoded as X.509 `SanType::URI` entries.
- **HTTP/2 Multiplexing & Flow Control (`src/dataplane/mux.rs`):**
  - **Receive Window Management:** In `H2TunnelStream::poll_read`, `self.recv_stream.flow_control().release_capacity(len)` **must** be called immediately as frames are read. Removing or delaying capacity release will stall large downloads when the HTTP/2 window exhausts.
  - **Keepalive & Window Sizes:** Maintain the 30-second HTTP/2 `PING` keepalive task and elevated initial stream/connection window sizes (`1 MiB` / `4 MiB`).
  - **Flow Posture Headers:** Every HTTP/2 `CONNECT` and `CONNECT-UDP` request must attach `x-acidex-*` headers via `FlowMetadataProvider::append_headers`.
  - **UDP Tunneling (`CONNECT-UDP` / RFC 9298 MASQUE):** Non-DNS corporate UDP flows in TUN mode use Extended `CONNECT` (`:protocol = "CONNECT-UDP"`, `:scheme = "https"`, `:authority = <proxy_host>`, `:path = "/.well-known/masque/udp/<host>/<port>/"`) with RFC 9297 `DATAGRAM` capsules (`Capsule Type = 0x00`, QUIC varint length `1 + payload.len()`, `Context ID = 0x00`).
- **ConfigSync over HTTP/1.1 mTLS (`src/control/sync.rs`):**
  - Unlike the data plane (which negotiates ALPN `h2`), `ConfigSync` communicates over mTLS using **HTTP/1.1** (`TlsConfig::for_http1`).
  - It sends a `POST` request with the serialized `AcidexPayload` JSON body and headers `x-zta-accept-config-schema-version: 2, 1`, `x-zta-enrollment-id`, `x-request-id`, and `If-None-Match` (when an ETag is cached).

---

## 2. Networking Stack, Fake-IP DNS & `systemd-resolved`

- **Strict Isolation of Corporate DNS Queries (`src/net/fakeip.rs`):**
  - When `RouteMatcher::matches_domain` identifies a domain as corporate:
    - `RecordType::A` queries return a synthetic IPv4 from `198.18.0.0/15` (`0xc6120001..=0xc613fffe`) with a short TTL (`5s`).
    - **All other query types (`AAAA`, `HTTPS` type 65, `TXT`, etc.) must immediately return an empty `NOERROR` (NODATA) response.**
    - **Never** forward corporate domain queries to the upstream public DNS resolver; doing so leaks internal hostnames and causes IPv6 connection timeout delays.
  - **EDNS0 Mirroring:** Always mirror the request's EDNS0 extensions (`set_dnssec_ok(false)`) in DNS responses so `systemd-resolved` does not downgrade or reject packets.
- **Linux TUN & Split-DNS Routing (`src/main.rs`, `src/net/tun_device.rs`, `src/net/sys_route.rs`):**
  - In Linux full-system mode, the TUN device (`ztna0` by default) must be brought up before binding the TUN-address DNS listener.
  - DNS listeners run on `127.0.0.1:53` (used as the target for `resolvectl dns <tun> 127.0.0.1` to avoid `rp_filter` / `firewalld` drops), on `<tun_ip>:53`, and inside the userspace `netstack-smoltcp` UDP/TCP port 53 handlers.
  - `SystemRouteManager::apply_routes` always routes `198.18.0.0/15` plus all policy CIDR subnets through the TUN device, adds the TUN interface to the `firewalld` `trusted` zone (if active), and cleans up routes/interfaces on shutdown (`SIGINT` / `SIGTERM`).
  - Redundant subdomains are pruned before passing `~<domain>` routing domains to `resolvectl domain` to keep `systemd-resolved` routing tables compact.

---

## 3. Cross-Platform Support, Privilege Model & Posture Spoofing

- **Linux vs. Windows Conditional Compilation (`Cargo.toml`, `src/net/`, `src/control/system_check.rs`):**
  - `tun` and `libc` are Linux-only dependencies (`[target.'cfg(target_os = "linux")'.dependencies]`).
  - Any code touching kernel TUN devices, `ip` / `resolvectl` / `firewall-cmd`, `libc::geteuid()`, or `/proc` must be gated behind `#[cfg(target_os = "linux")]` with appropriate non-Linux fallbacks (`#[cfg(not(target_os = "linux"))]`) so native Windows builds (`--proxy-only` SOCKS5h mode) compile cleanly.
- **Privilege Separation & Configuration Path Resolution (`src/config/mod.rs`, `src/control/system_check.rs`):**
  - **`enroll` runs unprivileged:** `check_enroll_privileges` blocks running `enroll` under `root`/`sudo` (unless `--allow-root` is passed) because desktop browsers fail to launch or capture SSO cookies under root, and config files would become root-owned.
  - **`run` under `sudo` resolves the real user's config:** When `sudo open-cisco-zta run` is executed on Linux, `ConfigManager::default_dir()` inspects `SUDO_USER` so that `/home/<SUDO_USER>/.config/open-cisco-zta` is used instead of `/root/.config/open-cisco-zta`. Preserve this behavior when modifying path resolution.
- **End-to-End OS Posture Spoofing (`src/plugins/acidex.rs`):**
  - `OsProfile` (`auto`, `linux`, `windows`) controls the `AcidexPayload` metadata.
  - Whenever posture fields or profiles are updated, ensure consistency across all three stages where posture is sent:
    1. Enrollment (`register_dha` in `src/control/enroll.rs`)
    2. Policy synchronization (`ConfigSync::sync_once` in `src/control/sync.rs`)
    3. Data plane stream establishment (`DefaultAcidexProvider` in `src/dataplane/mux.rs`)

---

## 4. Documentation Maintenance (`README.md`)

- **Always check `README.md` after making changes:** Whenever you add, modify, or remove CLI commands/flags, configuration files, environment variables, supported OS profiles, architectural modules, or build/runtime dependencies, inspect `README.md` and update it in the same change so user documentation remains accurate and in sync with the codebase.
