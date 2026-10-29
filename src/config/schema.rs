use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentState {
    pub org_id: String,
    #[serde(default)]
    pub duo_device_id: Option<String>,
    pub ztna_device_id: String,
    #[serde(default)]
    pub dha_base_url: Option<String>,
    pub user_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default, rename = "type")]
    pub enrollment_type: Option<String>,
    #[serde(default)]
    pub local_uid: Option<String>,
    #[serde(default)]
    pub enrollment_time: Option<String>,
    pub config_sync_url: String,
    #[serde(default)]
    pub config_etag: Option<String>,
    #[serde(default)]
    pub config_hash: Option<String>,
    #[serde(default)]
    pub config_sync_interval: Option<String>,
    #[serde(default)]
    pub last_config_sync_success_time: Option<String>,
    #[serde(default)]
    pub choice_id: Option<String>,
    #[serde(default)]
    pub certificate_expiration_time: Option<String>,
    #[serde(default)]
    pub certificate_state: Option<String>,
    #[serde(default)]
    pub client_cert_file: Option<String>,
    #[serde(default)]
    pub client_key_file: Option<String>,
    #[serde(default)]
    pub acme_dir_url: Option<String>,
    #[serde(default)]
    pub client_cert_alias: Option<String>,
    #[serde(default)]
    pub os_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaConfigWrapper {
    #[serde(rename = "ztnaConfig")]
    pub ztna_config: ZtnaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaConfig {
    #[serde(default)]
    pub global_metadata: Option<GlobalMetadata>,
    #[serde(default)]
    pub global_settings: Option<GlobalSettings>,
    #[serde(default)]
    pub network_fingerprints: Option<Vec<NetworkFingerprint>>,
    #[serde(default)]
    pub proxy_configs: Option<Vec<ProxyConfig>>,
    #[serde(default)]
    pub proxy_servers: Option<Vec<ProxyServer>>,
    #[serde(default)]
    pub resource_configs: Vec<ResourceConfig>,
    #[serde(default)]
    pub update_enrollment: Option<UpdateEnrollment>,
    #[serde(default)]
    pub version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalMetadata {
    #[serde(default)]
    pub org_name: Option<String>,
    #[serde(default)]
    pub profile_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(default)]
    pub exclude_local_lan: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub match_dns_domains: Vec<String>,
    #[serde(default)]
    pub match_dns_servers: Vec<String>,
    #[serde(default)]
    pub retry_interval: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub match_resource_configs: Vec<String>,
    #[serde(default)]
    pub proxy_server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyServer {
    pub id: String,
    pub label: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub cidr: Option<CidrFilter>,
    #[serde(default)]
    pub fqdn: Option<FqdnFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrFilter {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FqdnFilter {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEnrollment {
    #[serde(default)]
    pub config_sync_url: Option<String>,
}
