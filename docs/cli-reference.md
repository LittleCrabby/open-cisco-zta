# CLI Commands & Options Reference

This document provides the complete command-line interface (CLI) reference for **open-cisco-zta**, covering all subcommands, arguments, flags, default values, and environment variables.

---

## 📋 Command Overview

```text
open-cisco-zta [OPTIONS] <COMMAND>
```

### Global Options

| Flag / Option | Description |
| :--- | :--- |
| `-c, --config-dir <PATH>` | Custom configuration directory path (defaults to standard OS user directory). |
| `-V, --version` | Display version and git commit hash (e.g. `0.1.0 (git: abc1234)`). |
| `-h, --help` | Display command-line help and usage instructions. |

---

## 🔧 Subcommands

### 1. `enroll`

Bootstrap new client enrollment with the Cisco Secure Access tenant, authenticate via browser SSO, register device posture, and issue an mTLS client certificate via ACME.

```bash
open-cisco-zta enroll [OPTIONS]
```

#### Options & Flags

| Flag / Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--token <JWT>` | String | *None* | Pass corporate SSO JWT token directly to bypass automated browser login. |
| `--os-profile <PROFILE>`<br>*(alias: `--spoof-os`)* | String | `auto` | OS posture profile (`auto`, `linux`, `windows`). |
| `--allow-root` | Flag | `false` | Allow running enrollment as root/sudo (normally blocked to protect browser cookies and user permissions). |
| `-c, --config-dir <PATH>` | Path | `~/.config/open-cisco-zta` | Custom directory to save configuration and certificates. |

#### Examples

```bash
# Standard interactive enrollment (recommended, runs as normal user):
open-cisco-zta enroll

# Enroll while spoofing client OS posture as Linux:
open-cisco-zta enroll --os-profile linux

# Non-interactive enrollment passing a pre-acquired SSO JWT:
open-cisco-zta enroll --token "eyJhbGciOiJSUzI1NiIs..."

# Headless server enrollment running under root:
sudo open-cisco-zta enroll --allow-root
```

---

### 2. `run`

Run the ZTNA client daemon. Depending on privileges and flags, this starts a full-system Linux TUN interface with Split-DNS, or a local userspace SOCKS5h proxy server.

```bash
open-cisco-zta run [OPTIONS]
```

#### Options & Flags

| Flag / Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--proxy-only` | Flag | `false` | Run in userspace SOCKS5h proxy mode only (no TUN interface, no root/Administrator needed). On Windows, omit it to use Wintun TUN mode. |
| `-f, --force` | Flag | `false` | Force start even if conflicting official Cisco daemons (`csc_zta_agent`, `acsockd`) are detected. |
| `--os-profile <PROFILE>`<br>*(alias: `--spoof-os`)* | String | Profile from `enrollment.json` | Override client OS posture profile (`auto`, `linux`, `windows`). |
| `--socks-addr <IP:PORT>` | SocketAddr | `127.0.0.1:1080` | Local SOCKS5h proxy listen address. |
| `--dns-addr <IP:PORT>` | SocketAddr | `127.0.0.1:1053` | Embedded Fake-IP DNS server listen address. |
| `--upstream-dns <IP:PORT>` | SocketAddr | `1.1.1.1:53` | Upstream DNS resolver for non-corporate public domains. |
| `--tun-name <NAME>` | String | `ztna0` | Virtual TUN interface name (Linux and Windows). |
| `--tun-ip <IPV4>` | IPv4 | `100.64.0.1` | Local IPv4 address assigned to the TUN interface (Linux and Windows). |
| `-c, --config-dir <PATH>` | Path | `~/.config/open-cisco-zta` | Custom configuration directory path. |

#### Examples

```bash
# Linux full-system transparent TUN mode (requires root / sudo):
sudo open-cisco-zta run

# Linux unprivileged mode (no root needed, local SOCKS5h proxy on 127.0.0.1:1080):
open-cisco-zta run --proxy-only

# Windows full-system TUN mode (elevated PowerShell, wintun.dll next to the exe):
open-cisco-zta.exe run

# Windows unprivileged SOCKS5h proxy mode:
open-cisco-zta.exe run --proxy-only

# Custom SOCKS5 and DNS listen ports:
open-cisco-zta run --proxy-only --socks-addr 127.0.0.1:8080 --dns-addr 127.0.0.1:5353

# Bypass Cisco daemon conflict check:
sudo open-cisco-zta run --force
```

---

### 3. `status`

Inspect the current client enrollment state, downloaded routing policies, and certificate expiration.

```bash
open-cisco-zta status [OPTIONS]
```

#### Options & Flags

| Flag / Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c, --config-dir <PATH>` | Path | `~/.config/open-cisco-zta` | Custom configuration directory path. |

#### Example Output

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

### 4. `sync`

Trigger an immediate policy synchronization request to the Cisco ZTNA cloud proxy to download updated routing rules and proxy configurations.

```bash
open-cisco-zta sync [OPTIONS]
```

#### Options & Flags

| Flag / Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c, --config-dir <PATH>` | Path | `~/.config/open-cisco-zta` | Custom configuration directory path. |

#### Examples

```bash
# Trigger an immediate manual sync:
open-cisco-zta sync
```

---

## 🌐 Environment Variables

| Variable | Description |
| :--- | :--- |
| `OPEN_CISCO_ZTA_CONFIG_DIR` | Overrides the base configuration directory path. |
| `OPEN_CISCO_ZTA_NO_UPDATE_CHECK` | Set to `1` or `true` to disable background release update checks. |
| `CI` | When set to `1` or `true`, automatically disables release update checks. |
| `SUDO_USER` | On Linux, inspected when running under `sudo` to determine the user's home configuration directory. |
| `RUST_LOG` | Controls tracing log verbosity (e.g., `info`, `debug`, `trace`, `open_cisco_zta=debug`). |
