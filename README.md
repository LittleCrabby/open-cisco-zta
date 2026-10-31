# open-cisco-zta

**open-cisco-zta** is an open-source, high-performance alternative client for **Cisco Secure Access ZTNA (Zero Trust Network Access)** written in **Rust**. It runs as a standalone userspace binary without requiring proprietary background daemons, kernel extensions, or heavy agents.

It natively supports both **Linux** and **Windows**, complete with **OS Posture Spoofing** capabilities.

---

## ⚖️ Disclaimer

This project is an independent, clean-room open-source implementation and is **not** affiliated with, endorsed by, or sponsored by Cisco Systems, Inc. All trademarks and registered trademarks belong to their respective owners.

---

## ⚡ Quick Start (TL;DR)

1. **Enroll once** (authenticates via browser SSO and fetches mTLS certificates; run without `sudo`):
   ```bash
   open-cisco-zta enroll
   ```
2. **Start the tunnel**:
   - **Linux (Transparent TUN + Split-DNS):**
     ```bash
     sudo open-cisco-zta run
     ```
   - **Windows or unprivileged Linux (SOCKS5h proxy on `127.0.0.1:1080`):**
     ```bash
     open-cisco-zta run --proxy-only   # Linux
     open-cisco-zta.exe run            # Windows
     ```

---

## 🚀 Key Features

- **Cross-Platform Userspace Data Plane:**
  - **Linux:** Creates a virtual TUN interface (`ztna0`) backed by a userspace TCP/IP stack (`netstack-smoltcp`).
  - **Windows & Linux (Unprivileged):** Full-featured local SOCKS5h proxy server (`socks5h://127.0.0.1:1080`), allowing selective or system-wide tunneling without administrator/root privileges or kernel drivers.
  - Multiplexes TCP and UDP connections over mTLS HTTP/2 transport (`h2` over `tokio-openssl`) connected directly to Cisco Secure Access cloud proxies (`proxy-<org_id>.zpc.sse.cisco.com:443`).
  - Utilizes HTTP/2 `CONNECT` (TCP) and Extended `CONNECT-UDP` (RFC 8441 / RFC 9298 MASQUE with RFC 9297 `DATAGRAM` capsules for UDP protocols like Kerberos KDC port 88), proactive keepalive pinging (every 30s), dynamic flow-control capacity management (`WINDOW_UPDATE`), and flow posture injection (`x-acidex-*`).
- **OS Posture Spoofing (`--os-profile` / `--spoof-os`):**
  - Spoof client posture when connecting from Windows to appear as an authorized Linux client (`Ubuntu 22.04 LTS`, `linux-x86_64`), or vice versa.
  - Seamlessly injected across all protocol layers: Device Registration, DHA Posture Exchange (`acidex`), ConfigSync, and HTTP/2 stream headers.
- **Embedded Fake-IP DNS Engine (`198.18.0.0/15`):**
  - Resolves internal corporate domains (`*.corp.lan`, `*.internal.net`) into synthetic IPv4 addresses in the `198.18.0.0/15` range instantly.
  - Automatically synthesizes empty `NOERROR` responses for `AAAA` records to eliminate IPv6 timeout latency.
- **Rule Matching & Routing (`RouteMatcher`):**
  - Dynamically evaluates corporate CIDR subnets and FQDN rules with wildcard support (`*.internal.company.com`) and exclusion handling (`*.sse.cisco.com`).
- **Split-DNS & System Route Management (Linux):**
  - Automatically configures `systemd-resolved` Split-DNS routing domains and kernel routing tables.
  - Gracefully restores all routing states on `SIGINT` or `SIGTERM`.
- **Standalone Enrollment & ACME Certificate Lifecycle:**
  - Multi-stage enrollment:
    1. **Bootstrap Initialization** with RFC 9449 DPoP JWT (ES256).
    2. **Browser SSO Authentication** with automated SSO token capture via DevTools Protocol (Edge/Chrome/Brave) or manual fallback.
    3. **Device Registration** with Cisco Umbrella API.
    4. **DHA Posture Registration** with hardware posture (`acidex`) exchange.
    5. **ACME v2 Certificate Issuance** (RFC 8555 + Cisco custom `ZtnaUriList`) to generate client P-256 keys and obtain an official intermediate CA-signed client certificate.
- **Dynamic Policy Synchronization (`ConfigSync`):**
  - Automatically syncs routing policies from `/.well-known/zta-config/cisco/v2` with HTTP ETag caching and 304 Not Modified validation.
- **Automated Pre-Flight & Safety Checks:**
  - Prevents desktop browser session corruption and permission issues by disallowing accidental `sudo enroll` (`--allow-root` override available).
  - Validates privileges on Linux for TUN interface creation, prompting clear instructions for `sudo` or unprivileged `--proxy-only`.
  - Discovers active official Cisco Secure Client background daemons (`csc_zta_agent`, `acsockd`, `vpnagentd`) and prevents interface collisions (`-f` / `--force` override available).
- **Non-Blocking Update Notifications:**
  - Automatically notifies users on `stderr` when a new release is published on GitHub, without adding latency or blocking CLI command execution.
  - Employs a 24-hour local disk cache (`.update_cache.json`), GitHub redirect inspection to bypass API rate limits, and SemVer version comparison.
  - Can be disabled at any time via the `OPEN_CISCO_ZTA_NO_UPDATE_CHECK=1` or `CI=1` environment variables.

---

## 📦 Prerequisites & System Dependencies

### Linux

#### Build Dependencies
- **Rust Toolchain:** Stable Rust 1.75 or newer ([rustup.rs](https://rustup.rs/)).
- **C Compiler & Build Tools:** `gcc` or `clang`, `make`.
- **OpenSSL Development Headers:** `libssl-dev` or `openssl-devel`.
- **pkg-config:** To discover OpenSSL libraries.

**Debian / Ubuntu / Pop!_OS:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
```

**Fedora / RHEL / CentOS / AlmaLinux:**
```bash
sudo dnf install -y gcc gcc-c++ make pkgconfig openssl-devel
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -S --needed base-devel pkgconf openssl
```

#### Runtime Requirements (Linux)
- **Linux Kernel:** Kernel with `/dev/net/tun` support.
- **Network Tools:** `iproute2` (`ip` command) for full TUN mode.
- **DNS Resolver:** `systemd-resolved` (`resolvectl`) for Split-DNS in system TUN mode.
  *(Not required when running in `--proxy-only` mode!)*
- **Web Browser:** Google Chrome, Chromium, Brave, or Microsoft Edge for automated SSO enrollment.

---

### Windows

#### Build Dependencies
- **Rust Toolchain:** Install via [rustup.rs](https://rustup.rs/) (MSVC toolchain recommended).
- **C++ Build Tools:** Visual Studio C++ Build Tools (included with Visual Studio or "Build Tools for Visual Studio").
- **OpenSSL:** Not required if compiling with `--features vendored-openssl` (Rust will build OpenSSL statically from source!).

#### Runtime Requirements (Windows)
- Windows 10 / Windows 11 (64-bit).
- Microsoft Edge, Google Chrome, or Brave for browser SSO token capture.
- Python 3 with `websockets` (`pip install websockets`) for automated SSO cookie capture (optional; manual token entry is always available).

---

## 📥 Installation & Pre-built Packages

Pre-compiled packages for all major Linux distributions and Windows are published automatically on the **GitHub Releases** page.

### Debian / Ubuntu / Pop!_OS / Linux Mint (`.deb`)
```bash
sudo apt install ./open-cisco-zta_0.1.0-1_amd64.deb
```

### Fedora / RHEL / CentOS / AlmaLinux / Rocky (`.rpm`)
```bash
sudo dnf install ./open-cisco-zta-0.1.0-1.x86_64.rpm
```

### Arch Linux / Manjaro (`PKGBUILD`)
```bash
cd packaging/arch
makepkg -si
```

### Portable Linux Binary (`.tar.gz`)
```bash
tar -xzf open-cisco-zta-v0.1.0-linux-x86_64.tar.gz
cd open-cisco-zta-v0.1.0-linux-x86_64
sudo install -m 755 open-cisco-zta /usr/local/bin/
```

### Windows Standalone (`.zip`)
Download `open-cisco-zta-v0.1.0-windows-x86_64.zip`, extract `open-cisco-zta.exe`, and run directly in PowerShell.

---

### ⚙️ Optional Systemd Background Service (Linux)

Packages include a systemd service template that is disabled by default. If you prefer running `open-cisco-zta` as a persistent background daemon:
```bash
# Enroll your machine first:
open-cisco-zta enroll

# The daemon runs as root, so tell it where your enrollment lives
# (otherwise it looks in /root/.config/open-cisco-zta):
sudo systemctl edit open-cisco-zta
#   [Service]
#   Environment=OPEN_CISCO_ZTA_CONFIG_DIR=/home/<your-user>/.config/open-cisco-zta

# Start and enable daemon on boot:
sudo systemctl enable --now open-cisco-zta

# Check status and logs:
systemctl status open-cisco-zta
journalctl -u open-cisco-zta -f
```
*(You can always run `open-cisco-zta run` directly in your terminal at any time without using systemd).*

---

## 🔨 Building from Source

### Building on Linux
```bash
git clone https://github.com/LittleCrabby/open-cisco-zta.git
cd open-cisco-zta
cargo build --release
```
The compiled binary will be at `./target/release/open-cisco-zta`.

### Building on Windows
Run in PowerShell or Command Prompt:
```powershell
git clone https://github.com/LittleCrabby/open-cisco-zta.git
cd open-cisco-zta

# Build with vendored OpenSSL (recommended, no external OpenSSL install required):
cargo build --release --features vendored-openssl
```
The compiled executable will be at `.\target\release\open-cisco-zta.exe`.

### Running Unit Tests
```bash
cargo test
```

### Packaging Locally (.deb, .rpm, .tar.gz)
Build distribution packages on Linux with a single command:
```bash
./scripts/build-packages.sh
```
All packages and checksums will be placed in the `dist/` folder. For release tagging and CI/CD details, refer to [VERSIONING.md](VERSIONING.md).

---

## 🚀 Usage Guide

### 1. Client Enrollment (`enroll`)

Enroll your machine with your organization's Cisco Secure Access tenant:

```bash
# On Linux (run as your regular user, not sudo):
open-cisco-zta enroll

# On Windows:
open-cisco-zta.exe enroll
```

> [!IMPORTANT]
> **Run `enroll` as your regular user (without `sudo`).**
> Browser-based SSO authentication opens your desktop browser (Edge, Chrome, Brave) to capture the login cookie. Running under `sudo` will cause browser launch failures (sandbox/display permissions) and leave configuration files owned by root.
> *(If you need to enroll as root on a headless server, use `sudo open-cisco-zta enroll --allow-root`)*.

#### OS Profile & Posture Spoofing (`--os-profile`)
If your organization requires a Linux machine or enforces specific OS posture rules, you can spoof your client OS profile:

```bash
# Spoof as an authorized Linux client (Ubuntu 22.04 LTS, linux-x86_64):
open-cisco-zta enroll --os-profile linux

# Or explicitly as Windows:
open-cisco-zta enroll --os-profile windows
```

> [!TIP]
> `--spoof-os <profile>` is available as an alias for `--os-profile <profile>`.

**Enrollment Flow:**
1. Connects to Cisco Secure Access bootstrap endpoint using an ephemeral RFC 9449 DPoP key.
2. Automatically launches your default Chromium-based browser (Edge, Chrome, Brave) to the corporate SSO login portal.
3. Automatically captures the authenticated `elb-sso-jwt` cookie via Chrome DevTools Protocol.
4. Performs Device Registration and DHA Posture Registration (`acidex`).
5. Generates a local P-256 private key and CSR.
6. Connects to Cisco ACME CA, answers the `ztna-jwt` challenge, and retrieves the signed client mTLS certificate chain.
7. Saves all credentials and downloads initial routing policies to the configuration directory.

*(If you already have an SSO JWT token, pass it directly: `open-cisco-zta enroll --token <jwt>`)*

---

### 2. Running the Client (`run`)

#### Option A: Native Windows & Linux Unprivileged Mode (SOCKS5h)

On Windows, or on Linux without `sudo` privileges:
```bash
# On Linux (non-root):
open-cisco-zta run --proxy-only

# On Windows:
open-cisco-zta.exe run
```

This starts the high-performance local SOCKS5h proxy server on `socks5h://127.0.0.1:1080` (and Fake-IP DNS resolver on `127.0.0.1:1053`).

**How to use the tunnel:**
- **In Browsers (Firefox / Chrome / Edge):** Configure SOCKS5 proxy to `127.0.0.1:1080` with "Proxy DNS when using SOCKS v5" enabled. (Browser extensions like *Proxy SwitchyOmega* make this 1-click).
- **System-wide (Proxifier / Tun2Socks):** Route all corporate traffic or specific applications through SOCKS5 `127.0.0.1:1080`.
- **Command Line (curl / git):**
  ```bash
  curl -v -x socks5h://127.0.0.1:1080 https://argocd.platform.internal.lan
  git config --global http.proxy socks5h://127.0.0.1:1080
  ```
- **SSH:** Add to `~/.ssh/config`:
  ```ssh-config
  Host *.internal.lan
      ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
  ```

#### Option B: Linux Full System Mode (Virtual TUN + Split-DNS)

On Linux, full kernel TUN interface and automatic `systemd-resolved` Split-DNS provide transparent corporate access across your entire operating system without per-application proxy configuration:

```bash
sudo open-cisco-zta run
```

> [!TIP]
> **Built-in Pre-Flight Safety Checks:**
> When executing `run`, the client automatically performs pre-flight validation:
> 1. **Privilege Verification:** If run without `sudo` when TUN mode is requested, it provides clear guidance to run `sudo open-cisco-zta run` or switch to unprivileged proxy mode `open-cisco-zta run --proxy-only`.
> 2. **Cisco Daemon Conflict Detection:** It automatically checks if the official Cisco Secure Client daemons (`csc_zta_agent`, `acsockd`, `vpnagentd`) are running. If detected, it warns you to stop them (`sudo systemctl stop csc_zta_agent acsockd`). To bypass this check if you know what you are doing, pass `-f` / `--force`:
>    ```bash
>    sudo open-cisco-zta run --force
>    ```

**Output:**
```text
Open Cisco ZTNA All-in-One is active!
  - Interface : ztna0 (100.64.0.1)
  - DNS       : 100.64.0.1:53 (UDP/TCP) -> Split-DNS for ["corp.example.com", "internal.lan"]
  - SOCKS5h   : socks5h://127.0.0.1:1080
Press Ctrl+C to stop.
```

All corporate traffic is transparently tunneled. Pressing `Ctrl+C` cleans up routing and restores original network state.

---

### 3. Checking Status (`status`)

Inspect active enrollment details, downloaded routing rules, and certificate validity:

```bash
open-cisco-zta status
```

**Example Output:**
```text
=== Open Cisco ZTNA Client Status ===
Config Directory: "/home/user/.config/open-cisco-zta"

[Enrollment Information]
  Organization ID : 8354922
  User ID         : user@example.com
  ZTNA Device ID  : 1000000028bdab15
  Config Sync URL : https://proxy-8354922.zpc.sse.cisco.com/.well-known/zta-config/cisco/v2
  Sync Interval   : 10 min
  OS Profile      : linux

[Routing Policies]
  CIDR Include Subnets : 39
  FQDN Include Rules   : 216
  FQDN Exclude Rules   : 1

[Client Certificate]
  Certificate Path: "/home/user/.config/open-cisco-zta/client_cert.pem"
  Issuer    : organizationName=Cisco, commonName=PROD Internal ZTNA Sub CA 1 pca
  Valid From: Oct 28 20:47:07 2026 GMT
  Valid To  : Dec  2 20:47:07 2026 GMT
  SAN URIs  :
    - urn:cisco:sse:orgid:8354922
    - urn:cisco:sse:userid:user@example.com
    - urn:cisco:sse:ztna:deviceid:1000000028bdab15
```

---

### 4. Forcing Policy Synchronization (`sync`)

Manually trigger an updated routing policy sync from the Cisco ZTNA proxy:

```bash
open-cisco-zta sync
```

---

## 💻 CLI Commands & Options Reference

### Subcommands

| Subcommand | Description | Recommended Privileges |
| :--- | :--- | :--- |
| `enroll` | Bootstrap new client enrollment, SSO authentication, and ACME certificate issuance. | Regular user (`--allow-root` for root) |
| `run` | Run the ZTNA client daemon (TUN interface and/or local SOCKS5h proxy). | `sudo` (Linux TUN) or Regular user (`--proxy-only` / Windows) |
| `status` | Display current enrollment, active routing rules, and certificate expiration. | Any user |
| `sync` | Fetch updated routing rules and policies from Cisco ZTNA cloud proxy. | Any user |

### Subcommand Options & Flags

#### `open-cisco-zta enroll`
| Flag / Option | Default | Description |
| :--- | :--- | :--- |
| `--token <JWT>` | *None* | Pass corporate SSO JWT token directly to bypass browser automation. |
| `--os-profile <PROFILE>`<br>*(alias: `--spoof-os`)* | `auto` | OS posture spoofing profile (`auto`, `linux`, `windows`). |
| `--allow-root` | `false` | Allow running enrollment as root/sudo (normally blocked to protect user browser SSO). |
| `-c, --config-dir <PATH>` | `~/.config/open-cisco-zta` | Custom configuration directory path. |

#### `open-cisco-zta run`
| Flag / Option | Default | Description |
| :--- | :--- | :--- |
| `--proxy-only` | `false` | Run in userspace SOCKS5h proxy mode only (no TUN interface, no root needed). |
| `-f, --force` | `false` | Force start even if conflicting official Cisco daemons are detected. |
| `--os-profile <PROFILE>`<br>*(alias: `--spoof-os`)* | Enrollment profile | Override client OS posture profile (`auto`, `linux`, `windows`). |
| `--socks-addr <IP:PORT>` | `127.0.0.1:1080` | Local SOCKS5h proxy listen address. |
| `--dns-addr <IP:PORT>` | `127.0.0.1:1053` | Embedded Fake-IP DNS server listen address. |
| `--upstream-dns <IP:PORT>` | `1.1.1.1:53` | Upstream DNS resolver for non-corporate public domains. |
| `--tun-name <NAME>` | `ztna0` | Virtual TUN interface name (Linux). |
| `--tun-ip <IPV4>` | `100.64.0.1` | Local IP address assigned to TUN interface (Linux). |
| `-c, --config-dir <PATH>` | `~/.config/open-cisco-zta` | Custom configuration directory path. |

#### Global Options
| Flag | Description |
| :--- | :--- |
| `-V, --version` | Display version and git commit hash (e.g. `0.1.0 (git: abc1234)`). |
| `-h, --help` | Display command-line help and usage instructions. |
| `-c, --config-dir <PATH>` | Specify custom directory for configuration and certificates. |

The configuration directory can also be set with the `OPEN_CISCO_ZTA_CONFIG_DIR` environment variable (used by the systemd service); `--config-dir` takes precedence.

---

## 📁 Configuration Directory

All credentials, private keys, certificates, and cached routing tables are saved in:
- **Linux:** `~/.config/open-cisco-zta/`
- **Windows:** `%APPDATA%\open-cisco-zta\` (e.g. `C:\Users\<User>\AppData\Roaming\open-cisco-zta\`)

```text
open-cisco-zta/
├── enrollment.json        # Organization ID, Device ID, OS profile, and sync metadata
├── ztna_config.json       # Cached resource routing rules (CIDR / FQDN lists)
├── client_cert.pem        # Signed mTLS client certificate chain
├── client_key.pem         # Client EC P-256 private key
├── machine_id             # Persistent hardware UDID for posture stability
└── .update_cache.json     # Cached latest release version and check timestamp
```

---

## 🏗️ Project Architecture

```text
open-cisco-zta/
├── .github/workflows/       # GitHub Actions automated release pipeline
├── Cargo.toml               # Package definition, cargo-deb & cargo-generate-rpm metadata
├── LICENSE                  # GNU General Public License v3.0
├── packaging/
│   └── arch/PKGBUILD        # Arch Linux PKGBUILD packaging
├── scripts/
│   ├── build-packages.sh    # Local build script for .deb, .rpm, .tar.gz
│   └── release.sh           # SemVer release helper & git tagger
├── systemd/
│   └── open-cisco-zta.service # Systemd daemon service unit template
├── VERSIONING.md            # Semantic versioning & release guide
├── README.md
└── src/
    ├── main.rs              # CLI entry point (`enroll`, `run`, `status`, `sync`)
    ├── lib.rs               # Library root and exports
    ├── config/              # State persistence and Serde schemas
    │   ├── mod.rs           # ConfigManager (cross-platform path resolution)
    │   └── schema.rs        # EnrollmentState, ZtnaConfig, ResourceConfig
    ├── control/             # Management plane
    │   ├── browser.rs       # Automated DevTools SSO token capture (Edge/Chrome/Brave)
    │   ├── enroll.rs        # Bootstrap, device registration, and DHA posture registration
    │   ├── sync.rs          # Dynamic config synchronization with ETag caching
    │   ├── system_check.rs  # Pre-flight privilege checks & Cisco daemon conflict detection
    │   └── update_check.rs  # Non-blocking GitHub release update notifier & caching
    ├── crypto/              # Cryptographic operations
    │   ├── acme.rs          # RFC 8555 ACME client for Cisco custom ZtnaUriList
    │   ├── dpop.rs          # RFC 9449 DPoP proof signer (ES256)
    │   └── mod.rs           # OpenSSL mTLS connector and X.509 inspector
    ├── dataplane/           # Data plane tunneling and routing
    │   ├── mux.rs           # Http2MuxTransport (h2 connection pool & CONNECT stream tunnels)
    │   ├── router.rs        # Fast CIDR and wildcard domain matching
    │   └── socks5.rs        # Local SOCKS5h proxy server
    ├── net/                 # Networking layer
    │   ├── fakeip.rs        # Fake-IP pool (198.18.0.0/15) & micro-DNS server
    │   ├── sys_route.rs     # systemd-resolved and kernel route manager (Linux)
    │   └── tun_device.rs    # Virtual TUN interface & netstack-smoltcp bridge
    └── plugins/             # Posture and metadata plugins
        └── acidex.rs        # Device posture collector & OS Profile spoofing
```

---

## 🚫 Non-Goals & Scope Limitations (What This Tool Does NOT Do)

The official **Cisco Secure Client** (formerly Cisco AnyConnect) is a heavyweight, multi-component enterprise endpoint security suite. **`open-cisco-zta` is intentionally designed as a lean, specialized alternative specifically focused on Cisco Secure Access ZTNA (Private Applications over HTTP/2 mTLS)**.

To set clear expectations, here is what `open-cisco-zta` explicitly **does NOT** implement:

| Official Cisco Module / Feature | What Official Client Does | How `open-cisco-zta` Behaves (Out of Scope) |
| :--- | :--- | :--- |
| **Duo Device Health Application (DHA)** | Enforces local OS compliance (BitLocker/FileVault disk encryption, OS build/patch level, biometric checks, screen lock timeout, continuous Duo Push approvals). | **No local compliance checks.** We generate/spoof the required DHA posture payload (`urn:cisco:sse:dhaid:nil` or synthetic posture) to complete the ACME certificate trust exchange without running the Duo DHA daemon or querying local device health. |
| **Cisco AnyConnect Remote Access VPN** | Establishes traditional full-tunnel or split-tunnel IPsec (IKEv2) or SSL VPN connections to on-premises Cisco ASA, FTD, Meraki, or IOS-XE headends. | **No legacy VPN support.** Does not connect to Cisco ASA/FTD appliances. It communicates exclusively with cloud-native Cisco Secure Access SSE proxies (`*.zpc.sse.cisco.com:443`). |
| **Kernel Socket Filter / Driver (KDF / `acsockd`)** | Installs proprietary kernel drivers or eBPF socket filters to hook socket creation per-process and enforce granular endpoint access rules. | **Pure userspace only.** Runs with no proprietary kernel extensions, no eBPF, and no kernel drivers. It operates purely via standard OS TUN interfaces or unprivileged SOCKS5h proxying. |
| **Cisco Umbrella Roaming Security / SWG** | Intercepts all general Internet DNS traffic on `127.0.0.1:53`, routes it to Umbrella resolvers (`208.67.220.220`), enforces web content filtering, and proxies general Internet web traffic for TLS decryption/inspection. | **No general Internet interception.** Non-corporate Internet traffic is completely untouched. The embedded DNS resolver responds *only* to corporate domains defined in ZTNA policies; all other public DNS queries pass directly to your upstream DNS resolver. |
| **Cisco Secure Endpoint (formerly AMP)** | Full Next-Gen Antivirus (NGAV) and Endpoint Detection & Response (EDR), real-time file scanning, behavioral analysis, and malware quarantine. | **No antivirus or EDR.** We do not scan files, monitor processes, or provide malware protection. |
| **Cisco ISE Posture / HostScan (OPSWAT)** | Scans endpoints for installed antivirus definitions, registry values, personal firewall state, USB mass-storage restrictions, and executes remediation scripts. | **No deep posture scanning.** Only transmits baseline/spoofed Acidex metadata (`x-acidex-*`) required to satisfy cloud proxy HTTP/2 headers. |
| **Network Visibility Module (NVM)** | Collects IPFIX telemetry, endpoint process paths, user sessions, and sends flow data to Cisco Splunk / Stealthwatch for network surveillance. | **No user or process tracking.** Zero telemetry or flow logs are collected or reported. |
| **ThousandEyes Endpoint Agent** | Conducts automated synthetic network path tests, VoIP metric collection, and browser session monitoring. | **No synthetic monitoring.** No synthetic network probes or browser agents are bundled. |
| **Cisco Cloud Management (CCM) & Auto-Updates** | Connects to central Cisco cloud management for remote administrator policy pushes, silent background binary updates, and remote configuration locks. | **No remote management or silent auto-updates.** Completely under local user control. Binaries must be updated manually; a non-blocking notification banner is shown when a newer release is published. |
| **Desktop GUI / System Tray Applet** | Provides Qt-based desktop UI (`vpnui`), tray icons, popups, and graphical status graphs. | **Headless / CLI only.** Designed as a lean CLI daemon for servers, containers, developers, and terminal environments. |
| **Raw UDP Tunneling over ZTNA** | Some enterprise private applications require raw UDP datagram forwarding. | **TCP-only tunneling.** Cisco Secure Access ZTNA tunnels private application traffic over HTTP/2 `CONNECT` streams. We tunnel all TCP-based corporate applications (SSH, HTTP/HTTPS, databases, Git, Kubernetes, remote desktops); raw UDP outside DNS is not tunneled. |

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** (GPLv3). See the [LICENSE](LICENSE) file for the full text.
