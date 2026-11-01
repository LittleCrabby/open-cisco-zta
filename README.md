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
   - **Windows (Transparent TUN + Split-DNS, elevated PowerShell, requires `wintun.dll` next to the executable):**
     ```powershell
     open-cisco-zta.exe run
     ```
   - **Unprivileged Windows or Linux (SOCKS5h proxy on `127.0.0.1:1080`):**
     ```bash
     open-cisco-zta run --proxy-only
     ```

---

## 🚀 Key Features

- **Userspace Cross-Platform Data Plane:** Full transparent tunneling via a virtual TUN interface on Linux and Windows (`netstack-smoltcp`, Wintun on Windows), or an unprivileged local SOCKS5h proxy server on Windows and Linux without kernel extensions or root privileges.
- **High-Performance HTTP/2 & MASQUE Multiplexing:** Multiplexes TCP connections (`CONNECT`) and UDP datagrams (RFC 9298 MASQUE Extended `CONNECT-UDP`) over mTLS directly to Cisco Secure Access cloud proxies.
- **End-to-End OS Posture Spoofing:** Emulates authorized Linux or Windows client posture across all protocol stages (device registration, DHA posture, policy sync, and data plane stream headers).
- **Embedded Fake-IP DNS Engine:** Instant local resolution of corporate domains in `198.18.0.0/15` with zero internal hostname leakage and automatic IPv6 timeout suppression.
- **Automated Lifecycle & Dynamic Sync:** Effortless browser SSO authentication, custom ACME v2 certificate issuance, and dynamic policy synchronization with ETag caching.
- **Non-Blocking Update Checker:** Background release inspection that alerts users to newer versions without slowing down CLI execution.

> 📖 **Documentation:** For in-depth technical specifications, component deep-dives, and protocol invariants, see the [Full Features Documentation](docs/features.md) and [System Architecture](docs/architecture.md).

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
- For TUN mode: Administrator rights and [`wintun.dll`](https://www.wintun.net/) (amd64) placed next to `open-cisco-zta.exe`. Not needed for `--proxy-only`.
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

*(If you already have an SSO JWT token, pass it directly: `open-cisco-zta enroll --token <jwt>`)*.

> 📖 **Enrollment Details:** For the complete step-by-step lifecycle breakdown (DPoP, browser DevTools cookie interception, DHA posture exchange, and ACME challenge resolution), see [Client Enrollment & Authentication](docs/enrollment.md).

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

All corporate traffic is transparently tunneled. Pressing `Ctrl+C` cleans up routing and restores original network state.

---

### 3. Checking Status (`status`)

Inspect active enrollment details, downloaded routing rules, and certificate validity:

```bash
open-cisco-zta status
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
| `run` | Run the ZTNA client daemon (TUN interface and/or local SOCKS5h proxy). | `sudo` / Administrator (TUN) or Regular user (`--proxy-only`) |
| `status` | Display current enrollment, active routing rules, and certificate expiration. | Any user |
| `sync` | Fetch updated routing rules and policies from Cisco ZTNA cloud proxy. | Any user |

> 📖 **Full CLI Reference:** For comprehensive option tables, default parameters, environment variables, and usage examples for every command, see the [CLI Reference](docs/cli-reference.md).

> 📁 **Configuration & Architecture:** For details on configuration file formats, state schemas, and system internals, refer to [Configuration & State Persistence](docs/configuration.md) and [System Architecture](docs/architecture.md).

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

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** (GPLv3). See the [LICENSE](LICENSE) file for the full text.
