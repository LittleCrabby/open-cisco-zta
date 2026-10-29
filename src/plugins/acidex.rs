use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum OsProfile {
    #[default]
    Auto,
    Linux,
    Windows,
}

impl std::fmt::Display for OsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsProfile::Auto => write!(f, "auto"),
            OsProfile::Linux => write!(f, "linux"),
            OsProfile::Windows => write!(f, "windows"),
        }
    }
}

impl std::str::FromStr for OsProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(OsProfile::Auto),
            "linux" => Ok(OsProfile::Linux),
            "windows" | "win" => Ok(OsProfile::Windows),
            other => anyhow::bail!("Unknown OS profile: '{}'. Supported: auto, linux, windows", other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcidexPayload {
    pub status: OriginStatus,
    pub acidex: AcidexDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginStatus {
    #[serde(rename = "originTypeName")]
    pub origin_type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcidexDetail {
    pub client: ClientDetail,
    pub os: OsDetail,
    pub system: SystemDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDetail {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub global_udid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetail {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDetail {
    pub hostname: String,
    pub hardware_vendor: String,
    pub hardware_model: String,
    pub hardware_serial: String,
    pub udid: String,
}

fn read_sys_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn detect_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(h) = read_sys_file("/etc/hostname") {
            return h;
        }
    }
    "ZTA-Client".to_string()
}

fn detect_or_create_machine_id() -> String {
    let config_dir = crate::config::ConfigManager::default_dir();
    let machine_file = config_dir.join("machine_id");

    if let Ok(id) = std::fs::read_to_string(&machine_file) {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(uuid) = read_sys_file("/sys/class/dmi/id/product_uuid") {
            return uuid;
        }
        if let Some(id) = read_sys_file("/etc/machine-id") {
            return id;
        }
    }

    let new_id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::create_dir_all(&config_dir);
    let _ = std::fs::write(&machine_file, &new_id);
    new_id
}

fn detect_os_info() -> (String, String) {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let mut name = None;
        let mut version = None;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("NAME=") {
                name = Some(rest.trim_matches('"').to_string());
            } else if let Some(rest) = line.strip_prefix("VERSION=") {
                version = Some(rest.trim_matches('"').to_string());
            }
        }
        if let (Some(n), Some(v)) = (name, version) {
            return (n, v);
        }
    }
    ("Linux".to_string(), "Generic".to_string())
}

impl AcidexPayload {
    pub fn with_profile(profile: OsProfile) -> Self {
        let effective_profile = match profile {
            OsProfile::Auto => {
                #[cfg(target_os = "windows")]
                {
                    OsProfile::Windows
                }
                #[cfg(not(target_os = "windows"))]
                {
                    OsProfile::Linux
                }
            }
            p => p,
        };

        let hostname = detect_hostname();
        let udid = detect_or_create_machine_id();
        let global_udid = udid.replace('-', "").to_uppercase();

        match effective_profile {
            OsProfile::Linux => {
                let (os_name, os_version) = if cfg!(target_os = "linux") {
                    detect_os_info()
                } else {
                    ("Ubuntu 22.04.4 LTS".to_string(), "22.04".to_string())
                };

                let vendor = read_sys_file("/sys/class/dmi/id/sys_vendor")
                    .unwrap_or_else(|| "Dell Inc.".to_string());
                let model = read_sys_file("/sys/class/dmi/id/product_name")
                    .unwrap_or_else(|| "Latitude 5530".to_string());
                let serial = read_sys_file("/sys/class/dmi/id/product_serial")
                    .unwrap_or_else(|| "8V2KZ1".to_string());

                Self {
                    status: OriginStatus {
                        origin_type_name: "ztna_client".to_string(),
                    },
                    acidex: AcidexDetail {
                        client: ClientDetail {
                            name: "Zero Trust Access".to_string(),
                            version: "5.1.17.5300".to_string(),
                            platform: "linux-x86_64".to_string(),
                            global_udid,
                        },
                        os: OsDetail {
                            name: os_name,
                            version: os_version,
                            arch: "x86_64".to_string(),
                            platform: "linux".to_string(),
                        },
                        system: SystemDetail {
                            hostname,
                            hardware_vendor: vendor,
                            hardware_model: model,
                            hardware_serial: serial,
                            udid,
                        },
                    },
                }
            }
            OsProfile::Windows => {
                Self {
                    status: OriginStatus {
                        origin_type_name: "ztna_client".to_string(),
                    },
                    acidex: AcidexDetail {
                        client: ClientDetail {
                            name: "Zero Trust Access".to_string(),
                            version: "5.1.17.5300".to_string(),
                            platform: "win-x86_64".to_string(),
                            global_udid,
                        },
                        os: OsDetail {
                            name: "Windows 11 Pro".to_string(),
                            version: "10.0.22631".to_string(),
                            arch: "x86_64".to_string(),
                            platform: "win".to_string(),
                        },
                        system: SystemDetail {
                            hostname,
                            hardware_vendor: "Microsoft Corporation".to_string(),
                            hardware_model: "Surface Laptop".to_string(),
                            hardware_serial: "0123456789".to_string(),
                            udid,
                        },
                    },
                }
            }
            OsProfile::Auto => unreachable!(),
        }
    }
}

impl Default for AcidexPayload {
    fn default() -> Self {
        Self::with_profile(OsProfile::Auto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_profile_parsing() {
        assert_eq!("auto".parse::<OsProfile>().unwrap(), OsProfile::Auto);
        assert_eq!("linux".parse::<OsProfile>().unwrap(), OsProfile::Linux);
        assert_eq!("windows".parse::<OsProfile>().unwrap(), OsProfile::Windows);
        assert_eq!("win".parse::<OsProfile>().unwrap(), OsProfile::Windows);
    }

    #[test]
    fn test_spoofed_linux_profile() {
        let payload = AcidexPayload::with_profile(OsProfile::Linux);
        assert_eq!(payload.acidex.client.platform, "linux-x86_64");
        assert_eq!(payload.acidex.os.platform, "linux");
        assert_eq!(payload.acidex.os.arch, "x86_64");
        assert!(!payload.acidex.system.udid.is_empty());
        assert_eq!(
            payload.acidex.client.global_udid,
            payload.acidex.system.udid.replace('-', "").to_uppercase()
        );
    }

    #[test]
    fn test_spoofed_windows_profile() {
        let payload = AcidexPayload::with_profile(OsProfile::Windows);
        assert_eq!(payload.acidex.client.platform, "win-x86_64");
        assert_eq!(payload.acidex.os.platform, "win");
        assert_eq!(payload.acidex.os.name, "Windows 11 Pro");
        assert_eq!(payload.acidex.os.arch, "x86_64");
        assert!(!payload.acidex.system.udid.is_empty());
    }
}

