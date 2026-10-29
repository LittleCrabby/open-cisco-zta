pub mod acme;
pub mod dpop;

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use anyhow::bail;
#[cfg(target_os = "linux")]
use foreign_types::ForeignType;
#[cfg(target_os = "linux")]
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
#[cfg(target_os = "linux")]
use openssl::ssl::SslConnectorBuilder;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::ffi::{c_char, c_int, c_uchar, c_ulong, c_void, CString};
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

#[cfg(target_os = "linux")]
static PKCS11_PROVIDERS_INIT: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "linux")]
extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

#[cfg(target_os = "linux")]
const RTLD_NOW: c_int = 2;
#[cfg(target_os = "linux")]
const RTLD_LOCAL: c_int = 0;

#[cfg(target_os = "linux")]
#[link(name = "crypto")]
extern "C" {
    fn OSSL_STORE_open(
        uri: *const c_char,
        ui_method: *const c_void,
        ui_data: *mut c_void,
        post_process: *const c_void,
        post_process_data: *mut c_void,
    ) -> *mut c_void;
    fn OSSL_STORE_load(ctx: *mut c_void) -> *mut c_void;
    fn OSSL_STORE_INFO_get_type(info: *const c_void) -> c_int;
    fn OSSL_STORE_INFO_get1_PKEY(info: *const c_void) -> *mut c_void;
    fn OSSL_STORE_INFO_free(info: *mut c_void);
    fn OSSL_STORE_eof(ctx: *mut c_void) -> c_int;
    fn OSSL_STORE_close(ctx: *mut c_void) -> c_int;
}

#[cfg(target_os = "linux")]
const OSSL_STORE_INFO_PKEY: c_int = 4;

pub struct TlsConfig {
    pub cert_path: Option<std::path::PathBuf>,
    pub key_path: Option<std::path::PathBuf>,
    pub alpn_protocols: Vec<u8>,
}

impl TlsConfig {
    pub fn for_h2(cert_path: Option<&Path>, key_path: Option<&Path>) -> Self {
        Self {
            cert_path: cert_path.map(|p| p.to_path_buf()),
            key_path: key_path.map(|p| p.to_path_buf()),
            alpn_protocols: b"\x02h2".to_vec(),
        }
    }

    pub fn for_http1(cert_path: Option<&Path>, key_path: Option<&Path>) -> Self {
        Self {
            cert_path: cert_path.map(|p| p.to_path_buf()),
            key_path: key_path.map(|p| p.to_path_buf()),
            alpn_protocols: b"\x08http/1.1\x02h2".to_vec(),
        }
    }
}

/// Unseals `/opt/.cisco/certificates/pkcs11/keystoreblob.bin` via TPM2 and derives
/// the 32-byte raw PKCS#11 user PIN exactly as `csc_zta_agent` (`Pkcs11KeyStore::getLoginPins`) does:
///   master_pin = SHA256(tpm_secret)
///   user_pin   = SHA256(master_pin || b"system")
#[cfg(target_os = "linux")]
fn derive_cisco_tpm_user_pin(store_dir: &Path) -> Result<[u8; 32]> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let blob_path = Path::new("/opt/.cisco/certificates/pkcs11/keystoreblob.bin");
    let blob = fs::read(blob_path)
        .with_context(|| format!("Failed to read {:?}", blob_path))?;
    if blob.len() < 4 {
        bail!("keystoreblob.bin is too short ({} bytes)", blob.len());
    }

    let priv_len = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    let split_idx = 2 + priv_len;
    if blob.len() <= split_idx {
        bail!(
            "Invalid TPM2B_PRIVATE length {} in keystoreblob.bin (total {})",
            priv_len,
            blob.len()
        );
    }

    let tpm2b_priv = &blob[..split_idx];
    let tpm2b_pub = &blob[split_idx..];

    let _ = fs::create_dir_all(store_dir);
    let work_dir = store_dir.join(format!(
        ".tpm_work_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&work_dir)
        .with_context(|| format!("Failed to create private TPM work dir {:?}", work_dir))?;

    struct WorkDirGuard(std::path::PathBuf);
    impl Drop for WorkDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _guard = WorkDirGuard(work_dir.clone());

    let priv_file = work_dir.join("ks.priv");
    let pub_file = work_dir.join("ks.pub");
    let ctx_file = work_dir.join("ks.ctx");
    let prim_file = work_dir.join("prim.ctx");

    {
        use std::io::Write;
        let mut f_priv = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&priv_file)?;
        f_priv.write_all(tpm2b_priv)?;

        let mut f_pub = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pub_file)?;
        f_pub.write_all(tpm2b_pub)?;
    }

    // First try loading under persistent handle 0x81000001
    let mut loaded = Command::new("/usr/bin/tpm2_load")
        .args([
            "-T",
            "device:/dev/tpmrm0",
            "-C",
            "0x81000001",
            "-u",
        ])
        .arg(&pub_file)
        .arg("-r")
        .arg(&priv_file)
        .arg("-c")
        .arg(&ctx_file)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !loaded {
        // Fallback: recreate the standard TPM2 Owner Primary Key (rsa2048:aes128cfb)
        let prim_ok = Command::new("/usr/bin/tpm2_createprimary")
            .args([
                "-T",
                "device:/dev/tpmrm0",
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "rsa2048:aes128cfb",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
                "-c",
            ])
            .arg(&prim_file)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if prim_ok {
            loaded = Command::new("/usr/bin/tpm2_load")
                .args(["-T", "device:/dev/tpmrm0", "-C"])
                .arg(&prim_file)
                .arg("-u")
                .arg(&pub_file)
                .arg("-r")
                .arg(&priv_file)
                .arg("-c")
                .arg(&ctx_file)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        }
    }

    if !loaded {
        bail!("tpm2_load failed to load keystoreblob.bin");
    }

    let unseal_out = Command::new("/usr/bin/tpm2_unseal")
        .args(["-T", "device:/dev/tpmrm0", "-c"])
        .arg(&ctx_file)
        .output()
        .context("Failed to execute tpm2_unseal")?;

    if !unseal_out.status.success() {
        bail!(
            "tpm2_unseal failed: {}",
            String::from_utf8_lossy(&unseal_out.stderr)
        );
    }

    let tpm_secret = unseal_out.stdout;
    if tpm_secret.len() != 32 {
        bail!(
            "Unexpected unsealed TPM secret length: {} (expected 32)",
            tpm_secret.len()
        );
    }

    // Derive master_pin = SHA256(tpm_secret)
    let master_pin = Sha256::digest(&tpm_secret);

    // Derive user_pin = SHA256(master_pin || b"system")
    let mut hasher = Sha256::new();
    hasher.update(master_pin);
    hasher.update(b"system");
    let user_pin_digest = hasher.finalize();

    let mut user_pin = [0u8; 32];
    user_pin.copy_from_slice(&user_pin_digest);
    Ok(user_pin)
}

/// Ensures our isolated copy of `tpm2_pkcs11.sqlite3` in `store_dir` has an ASCII-safe PIN
/// (`"openzta"`) so OpenSSL's `pkcs11-provider` can log in via RFC 7512 `?pin-value=openzta`.
/// Never touches `/opt/.cisco/`.
#[cfg(target_os = "linux")]
fn ensure_local_pkcs11_pin(store_dir: &Path, tpm_lib: &Path) -> Result<()> {
    let marker = store_dir.join(".pin_initialized");
    if marker.exists() {
        return Ok(());
    }

    let user_pin = derive_cisco_tpm_user_pin(store_dir)
        .context("Failed to derive TPM2 PKCS#11 user PIN from keystoreblob.bin")?;

    let lib_cstr = CString::new(tpm_lib.to_string_lossy().as_bytes())?;
    unsafe {
        let handle = dlopen(lib_cstr.as_ptr(), RTLD_NOW | RTLD_LOCAL);
        if handle.is_null() {
            bail!("dlopen({:?}) failed", tpm_lib);
        }

        type CInitializeFn = unsafe extern "C" fn(*mut c_void) -> c_ulong;
        type CGetSlotListFn =
            unsafe extern "C" fn(c_uchar, *mut c_ulong, *mut c_ulong) -> c_ulong;
        type COpenSessionFn = unsafe extern "C" fn(
            c_ulong,
            c_ulong,
            *mut c_void,
            *const c_void,
            *mut c_ulong,
        ) -> c_ulong;
        type CSetPinFn = unsafe extern "C" fn(
            c_ulong,
            *const c_uchar,
            c_ulong,
            *const c_uchar,
            c_ulong,
        ) -> c_ulong;
        type CCloseSessionFn = unsafe extern "C" fn(c_ulong) -> c_ulong;
        type CFinalizeFn = unsafe extern "C" fn(*mut c_void) -> c_ulong;

        let sym_init = dlsym(handle, c"C_Initialize".as_ptr());
        let sym_slots = dlsym(handle, c"C_GetSlotList".as_ptr());
        let sym_open = dlsym(handle, c"C_OpenSession".as_ptr());
        let sym_set_pin = dlsym(handle, c"C_SetPIN".as_ptr());
        let sym_close = dlsym(handle, c"C_CloseSession".as_ptr());
        let sym_fin = dlsym(handle, c"C_Finalize".as_ptr());

        if sym_init.is_null()
            || sym_slots.is_null()
            || sym_open.is_null()
            || sym_set_pin.is_null()
            || sym_close.is_null()
            || sym_fin.is_null()
        {
            bail!("Missing required PKCS#11 symbols in {:?}", tpm_lib);
        }

        let c_init: CInitializeFn = std::mem::transmute(sym_init);
        let c_slots: CGetSlotListFn = std::mem::transmute(sym_slots);
        let c_open: COpenSessionFn = std::mem::transmute(sym_open);
        let c_set_pin: CSetPinFn = std::mem::transmute(sym_set_pin);
        let c_close: CCloseSessionFn = std::mem::transmute(sym_close);
        let c_fin: CFinalizeFn = std::mem::transmute(sym_fin);

        let rv = c_init(std::ptr::null_mut());
        // 0 = CKR_OK, 0x191 = CKR_CRYPTOKI_ALREADY_INITIALIZED
        if rv != 0 && rv != 0x191 {
            bail!("C_Initialize failed with CKR 0x{:x}", rv);
        }

        let mut slots = [0 as c_ulong; 8];
        let mut count: c_ulong = 8;
        let rv = c_slots(1, slots.as_mut_ptr(), &mut count);
        if rv != 0 || count == 0 {
            let _ = c_fin(std::ptr::null_mut());
            bail!("C_GetSlotList failed (rv=0x{:x}, count={})", rv, count);
        }

        let mut session: c_ulong = 0;
        // CKF_SERIAL_SESSION (0x04) | CKF_RW_SESSION (0x02) = 0x06
        let rv = c_open(
            slots[0],
            0x06,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut session,
        );
        if rv != 0 {
            let _ = c_fin(std::ptr::null_mut());
            bail!("C_OpenSession failed with CKR 0x{:x}", rv);
        }

        let new_pin = b"openzta";
        let rv = c_set_pin(
            session,
            user_pin.as_ptr(),
            user_pin.len() as c_ulong,
            new_pin.as_ptr(),
            new_pin.len() as c_ulong,
        );

        let _ = c_close(session);
        let _ = c_fin(std::ptr::null_mut());

        if rv != 0 {
            // Note: if the PIN on our local sqlite3 copy was already updated to "openzta",
            // C_SetPIN with the old raw pin returns CKR_PIN_INCORRECT (0xa0).
            tracing::debug!(
                "C_SetPIN returned 0x{:x} (local sqlite3 copy may already use 'openzta' PIN)",
                rv
            );
        } else {
            tracing::info!(
                "Successfully initialized local PKCS#11 token PIN in {:?}",
                store_dir
            );
        }
        let _ = fs::write(&marker, b"ok\n");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn load_private_key_via_ossl_store(builder: &mut SslConnectorBuilder, uri: &str) -> Result<()> {
    let c_uri = CString::new(uri)?;
    unsafe {
        let store_ctx = OSSL_STORE_open(
            c_uri.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        if store_ctx.is_null() {
            let err = openssl::error::ErrorStack::get();
            bail!("OSSL_STORE_open failed for URI '{}': {}", uri, err);
        }

        let mut found_pkey: *mut c_void = std::ptr::null_mut();
        while OSSL_STORE_eof(store_ctx) == 0 {
            let info = OSSL_STORE_load(store_ctx);
            if info.is_null() {
                break;
            }
            let info_type = OSSL_STORE_INFO_get_type(info);
            if info_type == OSSL_STORE_INFO_PKEY {
                found_pkey = OSSL_STORE_INFO_get1_PKEY(info);
                OSSL_STORE_INFO_free(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
        }
        let _ = OSSL_STORE_close(store_ctx);

        if found_pkey.is_null() {
            let err = openssl::error::ErrorStack::get();
            bail!("No EVP_PKEY found in OSSL_STORE for URI '{}': {}", uri, err);
        }

        let pkey: PKey<Private> = PKey::from_ptr(found_pkey as *mut _);
        builder
            .set_private_key(&pkey)
            .context("SSL_CTX_use_PrivateKey failed")?;
        builder
            .check_private_key()
            .context("SSL_CTX_check_private_key failed (key does not match client cert)")?;
    }
    Ok(())
}

pub fn create_ssl_connector(config: &TlsConfig) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .context("Failed to create OpenSSL SslConnector builder")?;

    // Enable TLS 1.2 and TLS 1.3
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;

    // Set ALPN
    if !config.alpn_protocols.is_empty() {
        builder
            .set_alpn_protos(&config.alpn_protocols)
            .context("Failed to set ALPN protocols")?;
    }

    // Load custom Cisco CA if available
    let cisco_ca_dir = Path::new("/opt/.cisco/certificates/ca");
    if cisco_ca_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(cisco_ca_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                    if let Ok(pem_bytes) = fs::read(&path) {
                        if let Ok(cert) = openssl::x509::X509::from_pem(&pem_bytes) {
                            let _ = builder.cert_store_mut().add_cert(cert);
                        }
                    }
                }
            }
        }
    }

    // Load Client Certificate Chain (Leaf + Intermediate CA)
    if let Some(ref cert_path) = config.cert_path {
        if cert_path.exists() {
            builder
                .set_certificate_chain_file(cert_path)
                .with_context(|| {
                    format!("Failed to load client certificate chain from {:?}", cert_path)
                })?;
            tracing::info!("Loaded client certificate chain from {:?}", cert_path);
        }
    }

    // Load Client Key
    #[allow(unused_mut, unused_assignments)]
    let mut key_loaded = false;
    if let Some(ref key_path) = config.key_path {
        if key_path.exists() {
            builder
                .set_private_key_file(key_path, SslFiletype::PEM)
                .with_context(|| format!("Failed to load client private key from {:?}", key_path))?;
            tracing::info!("Loaded client private key from {:?}", key_path);
            key_loaded = true;
        }
    }

    #[cfg(target_os = "linux")]
    if !key_loaded {
        let store_dir = config
            .key_path
            .as_deref()
            .and_then(|p| p.parent())
            .or_else(|| config.cert_path.as_deref().and_then(|p| p.parent()))
            .map(|p| p.to_path_buf())
            .unwrap_or_else(crate::config::ConfigManager::default_dir);

        let tpm_lib = store_dir.join("libtpm2_pkcs11.so");
        if tpm_lib.exists() {
            PKCS11_PROVIDERS_INIT.get_or_init(|| {
                std::env::set_var("PKCS11_PROVIDER_MODULE", &tpm_lib);
                std::env::set_var("TPM2_PKCS11_TCTI", "device:/dev/tpmrm0");
                if store_dir.join("tpm2_pkcs11.sqlite3").exists() {
                    std::env::set_var("TPM2_PKCS11_STORE", &store_dir);
                } else {
                    std::env::set_var("TPM2_PKCS11_STORE", "/opt/.cisco/certificates/pkcs11");
                }

                if let Err(e) = ensure_local_pkcs11_pin(&store_dir, &tpm_lib) {
                    tracing::warn!("Could not initialize local TPM2 PKCS#11 PIN: {:?}", e);
                }

                match openssl::provider::Provider::try_load(None, "default", true) {
                    Ok(p) => std::mem::forget(p),
                    Err(e) => tracing::warn!("Failed to load OpenSSL default provider: {:?}", e),
                }
                match openssl::provider::Provider::try_load(None, "pkcs11", true) {
                    Ok(p) => {
                        std::mem::forget(p);
                        tracing::info!("Loaded OpenSSL 3 pkcs11 provider (kept alive)");
                    }
                    Err(e) => tracing::warn!("Failed to load OpenSSL pkcs11 provider: {:?}", e),
                }
                true
            });

            let uris = [
                "pkcs11:token=com.cisco.secureclient.token;object=com.cisco.secureclient.privatekey;type=private?pin-value=openzta",
                "pkcs11:object=com.cisco.secureclient.privatekey;type=private?pin-value=openzta",
            ];

            for uri in uris {
                match load_private_key_via_ossl_store(&mut builder, uri) {
                    Ok(()) => {
                        tracing::info!(
                            "Loaded and verified TPM2 PKCS#11 client private key via OSSL_STORE"
                        );
                        key_loaded = true;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("OSSL_STORE key load attempt failed: {:?}", e);
                    }
                }
            }

            if !key_loaded {
                tracing::error!(
                    "Failed to load client private key from TPM2 PKCS#11 store! mTLS will fail."
                );
            }
        }
    }

    Ok(builder.build())
}

pub fn inspect_certificate(cert_path: &Path) -> Result<CertInfo> {
    let data = fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate at {:?}", cert_path))?;
    let cert = openssl::x509::X509::from_pem(&data)
        .context("Failed to parse X509 PEM certificate")?;

    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            let k = e.object().to_string();
            let v = String::from_utf8_lossy(e.data().as_slice()).to_string();
            format!("{k}={v}")
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            let k = e.object().to_string();
            let v = String::from_utf8_lossy(e.data().as_slice()).to_string();
            format!("{k}={v}")
        })
        .collect::<Vec<_>>()
        .join(", ");

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let mut san_entries = Vec::new();
    if let Some(san) = cert.subject_alt_names() {
        for name in san {
            if let Some(uri) = name.uri() {
                san_entries.push(uri.to_string());
            } else if let Some(dns) = name.dnsname() {
                san_entries.push(dns.to_string());
            }
        }
    }

    Ok(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        san_entries,
    })
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub san_entries: Vec<String>,
}
