# Configuration Directory & State Persistence

This document explains the configuration directory layout, file formats, and state schemas used by **open-cisco-zta**.

---

## 📁 Directory Paths & Resolution

`open-cisco-zta` stores client state, cryptographic keys, certificates, and cached policy tables in a standard OS configuration directory:

| Operating System / Context | Default Directory Path |
| :--- | :--- |
| **Linux (Normal user)** | `~/.config/open-cisco-zta/` (`$HOME/.config/open-cisco-zta/`) |
| **Linux (via `sudo`)** | `/home/<SUDO_USER>/.config/open-cisco-zta/` |
| **Linux (Root / System Service)** | `/root/.config/open-cisco-zta/` *(unless overridden)* |
| **Windows** | `%APPDATA%\open-cisco-zta\` (e.g., `C:\Users\<User>\AppData\Roaming\open-cisco-zta\`) |

---

### Path Resolution Precedence

When resolving the configuration directory path, [`ConfigManager::default_dir()`](file:///home/crabby/Experiments/open-cisco-zta/src/config/mod.rs#L49-L73) evaluates candidate paths in the following priority order:

1. **CLI Flag (`-c` / `--config-dir <PATH>`)**: Highest priority; explicitly overrides all environment variables and platform defaults for that invocation.
2. **Environment Variable (`OPEN_CISCO_ZTA_CONFIG_DIR`)**: Checked if no CLI flag is provided. Useful for persistent terminal sessions, automated scripts, and systemd service units.
3. **Windows Environment Variables**: Checks `%APPDATA%\open-cisco-zta`, followed by `%USERPROFILE%\.config\open-cisco-zta`.
4. **Linux `sudo` Invocation (`SUDO_USER`)**: When running under `sudo` on Linux, the daemon inspects the `SUDO_USER` variable and resolves that user's home directory via `libc::getpwnam_r` (`/home/<SUDO_USER>/.config/open-cisco-zta`). This ensures an unprivileged `open-cisco-zta enroll` works seamlessly with `sudo open-cisco-zta run`.
5. **Standard User Fallback (`HOME`)**: Resolves `$HOME/.config/open-cisco-zta` (defaulting to `/root/.config/open-cisco-zta` when run directly as root without `SUDO_USER`).

---

### How to Change the Configuration Directory

You can customize or relocate the configuration directory using one of three approaches:

#### 1. Command-Line Option (`-c` / `--config-dir`)

Pass the `-c` or `--config-dir` argument directly to any subcommand (`enroll`, `run`, `status`, `sync`). This option takes the highest precedence:

```bash
# Enroll using a custom path:
open-cisco-zta enroll --config-dir /var/lib/open-cisco-zta

# Run the tunnel daemon pointing to that directory:
sudo open-cisco-zta run -c /var/lib/open-cisco-zta

# Inspect status or trigger a manual policy sync:
open-cisco-zta status -c /var/lib/open-cisco-zta
open-cisco-zta sync -c /var/lib/open-cisco-zta
```

#### 2. Environment Variable (`OPEN_CISCO_ZTA_CONFIG_DIR`)

Set the `OPEN_CISCO_ZTA_CONFIG_DIR` environment variable to apply a custom path globally to all commands without supplying `-c` on each call:

```bash
# Export in current shell session:
export OPEN_CISCO_ZTA_CONFIG_DIR=/custom/path/open-cisco-zta
open-cisco-zta run

# Or pass inline for a single command:
OPEN_CISCO_ZTA_CONFIG_DIR=/custom/path/open-cisco-zta open-cisco-zta status
```

#### 3. Systemd Service Unit Drop-in (Linux Background Daemon)

When running `open-cisco-zta` as a persistent background daemon via systemd ([`systemd/open-cisco-zta.service`](file:///home/crabby/Experiments/open-cisco-zta/systemd/open-cisco-zta.service)), the service runs directly as `root` outside an interactive desktop user session. Consequently:
- `SUDO_USER` is **not** set.
- Without an override, the service searches for enrollment files in `/root/.config/open-cisco-zta/`.
- Client enrollment must be executed as an unprivileged user (`open-cisco-zta enroll`) to launch desktop browsers and capture SSO cookies, meaning your credentials reside in `/home/<your-user>/.config/open-cisco-zta`.

To point the systemd service to your user configuration directory, create a systemd drop-in file:

```bash
# Edit drop-in override for open-cisco-zta service:
sudo systemctl edit open-cisco-zta
```

In the editor that opens, insert the following configuration:

```ini
[Service]
Environment=OPEN_CISCO_ZTA_CONFIG_DIR=/home/<your-user>/.config/open-cisco-zta
```

Replace `<your-user>` with your Linux username. Then reload systemd and start the service:

```bash
# Reload systemd manager configuration:
sudo systemctl daemon-reload

# Enable and start service on boot:
sudo systemctl enable --now open-cisco-zta

# Inspect status and runtime logs:
systemctl status open-cisco-zta
journalctl -u open-cisco-zta -f
```

> [!NOTE]
> **Filesystem Permissions & `CAP_DAC_OVERRIDE`:**
> User home directories are typically restricted to `0700` or `0710` permissions, and `client_key.pem` is created with `0600` permissions. The provided [`open-cisco-zta.service`](file:///home/crabby/Experiments/open-cisco-zta/systemd/open-cisco-zta.service) includes `CAP_DAC_OVERRIDE` in `CapabilityBoundingSet`. This allows the root-level daemon to traverse user home directories, read the mTLS private keys, and update policy files (`enrollment.json`, `ztna_config.json`) during background syncs without requiring permission compromises.

---

## 📄 File Inventory

A fully enrolled client directory contains the following files:

```text
open-cisco-zta/
├── enrollment.json        # Identity, device IDs, URLs, and synchronization state
├── ztna_config.json       # Cached routing rules (CIDR subnets and FQDNs)
├── client_cert.pem        # Signed mTLS client certificate chain
├── client_key.pem         # Client EC P-256 private key (PEM format)
├── machine_id             # Persistent hardware UDID for posture stability
└── .update_cache.json     # Cached latest release version and check timestamp
```

---

## 📝 File Details & Schemas

### 1. `enrollment.json`

Stores tenant identifiers, endpoint metadata, URLs, and certificate metadata:

```json
{
  "org_id": "8354922",
  "duo_device_id": "dha-device-uuid-1234",
  "ztna_device_id": "1000000028bdab15",
  "dha_base_url": "https://dha.ztna.sse.cisco.com",
  "user_id": "user@example.com",
  "label": null,
  "type": "CiscoSecureAccess",
  "local_uid": "user",
  "enrollment_time": "2026-10-28T20:47:05Z",
  "config_sync_url": "https://proxy-8354922.zpc.sse.cisco.com/.well-known/zta-config/cisco/v2",
  "config_etag": "\"W/abcdef123456\"",
  "config_hash": "a1b2c3d4...",
  "config_sync_interval": "600",
  "last_config_sync_success_time": "2026-10-28T20:47:10Z",
  "choice_id": "cisco-secure-access/default",
  "certificate_expiration_time": "2026-12-02T20:47:07Z",
  "certificate_state": "Valid",
  "client_cert_file": "client_cert.pem",
  "client_key_file": "client_key.pem",
  "acme_dir_url": "https://prod.acme.sse.cisco.com/directory",
  "client_cert_alias": "cisco-zta-client-cert",
  "os_profile": "linux"
}
```

Key fields:
- `org_id`: Cisco Secure Access tenant / organization identifier.
- `ztna_device_id`: Canonical device ID issued by Cisco Umbrella.
- `config_sync_url`: Cloud URL used for dynamic policy sync via HTTP/1.1 mTLS.
- `config_etag`: ETag string received during the last successful policy sync.
- `os_profile`: OS posture profile selected during enrollment (`auto`, `linux`, `windows`).

---

### 2. `ztna_config.json`

Contains the cached policy payload received from `config_sync_url`. Contains routing definitions:

```json
{
  "ztnaConfig": {
    "version": 2,
    "resource_configs": [
      {
        "id": "res-101",
        "name": "Internal Platform Git",
        "description": "GitLab Internal Services",
        "addresses": [
          { "type": "fqdn", "value": "*.gitlab.internal.lan" },
          { "type": "cidr", "value": "10.40.0.0/16" }
        ],
        "ports": [
          { "protocol": "tcp", "port_ranges": ["22", "80", "443"] }
        ]
      }
    ],
    "proxy_servers": [
      {
        "host": "proxy-8354922.zpc.sse.cisco.com",
        "port": 443
      }
    ]
  }
}
```

- Parsed by `RouteMatcher` to determine which destinations belong to private applications and must be tunneled.

---

### 3. `client_cert.pem` & `client_key.pem`

- **`client_key.pem`:** Standard PKCS#8 or SEC1 PEM-encoded EC P-256 private key. Protected with standard user file permissions (`0600` on Unix).
- **`client_cert.pem`:** X.509 certificate chain returned by the Cisco ACME CA during enrollment.
  - The leaf certificate includes mandatory SAN URIs (`urn:cisco:sse:orgid:...`, `urn:cisco:sse:userid:...`, `urn:cisco:sse:ztna:deviceid:...`).
  - Used for mutual TLS authentication on both the HTTP/2 data plane and HTTP/1.1 policy sync.

---

### 4. `machine_id`

A plain-text string containing a persistent UUID v4 generated on first run. Used as a stable hardware identifier in `AcidexPayload` to ensure posture consistency across client restarts.

---

### 5. `.update_cache.json`

Used by the non-blocking background update checker to avoid redundant network requests:

```json
{
  "latest_version": "0.2.0",
  "checked_at": 1793444400
}
```

- When the cache is less than 24 hours old, no background network request is performed.
