# Configuration Directory & State Persistence

This document explains the configuration directory layout, file formats, and state schemas used by **open-cisco-zta**.

---

## 📁 Directory Paths

`open-cisco-zta` stores client state, cryptographic keys, certificates, and cached policy tables in a standard OS configuration directory:

| Operating System | Default Directory Path |
| :--- | :--- |
| **Linux (Normal user)** | `~/.config/open-cisco-zta/` |
| **Linux (via `sudo`)** | `/home/<SUDO_USER>/.config/open-cisco-zta/` |
| **Windows** | `%APPDATA%\open-cisco-zta\` (e.g., `C:\Users\<User>\AppData\Roaming\open-cisco-zta\`) |

### Path Resolution Invariant (`SUDO_USER`)
When running `sudo open-cisco-zta run` on Linux, the configuration manager inspects the `SUDO_USER` environment variable and resolves that user's home directory via `libc::getpwnam_r`. This allows a user to run `open-cisco-zta enroll` unprivileged as their standard desktop user, and then execute `sudo open-cisco-zta run` without losing access to their configuration or having to duplicate certificates into `/root/.config/open-cisco-zta/`.

### Overriding the Configuration Directory
You can override the configuration path using either:
- The `-c` or `--config-dir` CLI option:
  ```bash
  open-cisco-zta run --config-dir /custom/path/open-cisco-zta
  ```
- The `OPEN_CISCO_ZTA_CONFIG_DIR` environment variable:
  ```bash
  export OPEN_CISCO_ZTA_CONFIG_DIR=/custom/path/open-cisco-zta
  ```

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
