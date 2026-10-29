pub mod schema;

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
pub use schema::{EnrollmentState, ZtnaConfig, ZtnaConfigWrapper};

static CUSTOM_CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

#[cfg(target_os = "linux")]
fn lookup_user_home_dir(username: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};

    let c_user = CString::new(username).ok()?;
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];

        let rc = libc::getpwnam_r(
            c_user.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() && !pwd.pw_dir.is_null() {
            let dir_str = CStr::from_ptr(pwd.pw_dir).to_str().ok()?;
            if !dir_str.is_empty() {
                return Some(PathBuf::from(dir_str));
            }
        }
    }
    None
}

pub struct ConfigManager {
    base_dir: PathBuf,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    pub fn default_dir() -> PathBuf {
        if let Some(custom) = CUSTOM_CONFIG_DIR.get() {
            custom.clone()
        } else if let Ok(custom) = std::env::var("OPEN_CISCO_ZTA_CONFIG_DIR") {
            PathBuf::from(custom)
        } else if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join("open-cisco-zta")
        } else if let Ok(userprofile) = std::env::var("USERPROFILE") {
            PathBuf::from(userprofile).join(".config").join("open-cisco-zta")
        } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if sudo_user != "root" {
                #[cfg(target_os = "linux")]
                if let Some(home) = lookup_user_home_dir(&sudo_user) {
                    return home.join(".config").join("open-cisco-zta");
                }
                PathBuf::from(format!("/home/{sudo_user}/.config/open-cisco-zta"))
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
                PathBuf::from(home).join(".config").join("open-cisco-zta")
            }
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config").join("open-cisco-zta")
        }
    }

    pub fn new() -> Self {
        Self {
            base_dir: Self::default_dir(),
        }
    }

    pub fn with_dir<P: Into<PathBuf>>(dir: P) -> Self {
        let base_dir = dir.into();
        let _ = CUSTOM_CONFIG_DIR.set(base_dir.clone());
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn enrollment_path(&self) -> PathBuf {
        let primary = self.base_dir.join("enrollment.json");
        if primary.exists() {
            primary
        } else if let Some(official) = Self::find_official_enrollment_file() {
            official
        } else {
            primary
        }
    }

    pub fn ztna_config_path(&self) -> PathBuf {
        let primary = self.base_dir.join("ztna_config.json");
        if primary.exists() {
            primary
        } else if let Some(official) = Self::find_official_config_file() {
            official
        } else {
            primary
        }
    }

    pub fn cert_path(&self) -> PathBuf {
        self.base_dir.join("client_cert.pem")
    }

    pub fn key_path(&self) -> PathBuf {
        self.base_dir.join("client_key.pem")
    }

    fn find_official_enrollment_file() -> Option<PathBuf> {
        let mut candidates = vec![PathBuf::from("/opt/cisco/secureclient/zta/enrollments")];
        if let Ok(pd) = std::env::var("ProgramData") {
            candidates.push(PathBuf::from(pd).join("Cisco").join("Cisco Secure Client").join("ZTA").join("enrollments"));
        }
        for dir in candidates {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                        return Some(path);
                    }
                }
            }
        }
        None
    }

    fn find_official_config_file() -> Option<PathBuf> {
        let mut candidates = vec![PathBuf::from("/opt/cisco/secureclient/zta/enrollments/cached_configs")];
        if let Ok(pd) = std::env::var("ProgramData") {
            candidates.push(PathBuf::from(pd).join("Cisco").join("Cisco Secure Client").join("ZTA").join("enrollments").join("cached_configs"));
        }
        for dir in candidates {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                        return Some(path);
                    }
                }
            }
        }
        None
    }

    pub fn load_enrollment(&self) -> Result<EnrollmentState> {
        let path = self.enrollment_path();
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read enrollment file at {:?}", path))?;
        let state: EnrollmentState = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse enrollment json at {:?}", path))?;
        Ok(state)
    }

    pub fn load_ztna_config(&self) -> Result<ZtnaConfig> {
        let path = self.ztna_config_path();
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read ztna config at {:?}", path))?;
        let wrapper: ZtnaConfigWrapper = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse ztna config json at {:?}", path))?;
        Ok(wrapper.ztna_config)
    }

    pub fn save_enrollment(&self, state: &EnrollmentState) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("Failed to create config dir {:?}", self.base_dir))?;
        let path = self.base_dir.join("enrollment.json");
        let content = serde_json::to_string_pretty(state)?;
        fs::write(&path, content)?;
        Ok(())
    }

    pub fn save_ztna_config(&self, config: &ZtnaConfig) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("Failed to create config dir {:?}", self.base_dir))?;
        let path = self.base_dir.join("ztna_config.json");
        let wrapper = ZtnaConfigWrapper {
            ztna_config: config.clone(),
        };
        let content = serde_json::to_string_pretty(&wrapper)?;
        fs::write(&path, content)?;
        Ok(())
    }
}
