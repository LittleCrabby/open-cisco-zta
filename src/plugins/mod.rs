pub mod acidex;

use anyhow::Result;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::net::SocketAddr;
pub use acidex::{AcidexPayload, OsProfile};

#[derive(Debug, Clone)]
pub struct FlowInfo {
    pub src_addr: Option<SocketAddr>,
    pub dst_host: String,
    pub dst_port: u16,
}

pub trait FlowMetadataProvider: Send + Sync {
    fn append_headers(&self, flow: &FlowInfo, headers: &mut HeaderMap);
}

pub trait PostureProvider: Send + Sync {
    fn handle_stale_posture(&self, proxy_status: &str) -> Result<()>;
}

pub trait ProxyAuthProvider: Send + Sync {
    fn handle_407(&self, target: &str) -> Result<Option<HeaderValue>>;
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAcidexProvider {
    pub payload: AcidexPayload,
}

impl DefaultAcidexProvider {
    pub fn new() -> Self {
        Self {
            payload: AcidexPayload::default(),
        }
    }

    pub fn with_profile(profile: OsProfile) -> Self {
        Self {
            payload: AcidexPayload::with_profile(profile),
        }
    }
}

impl FlowMetadataProvider for DefaultAcidexProvider {
    fn append_headers(&self, _flow: &FlowInfo, headers: &mut HeaderMap) {
        let h = &self.payload.acidex;
        let mut insert_str = |k: &'static str, v: &str| {
            let name = HeaderName::from_static(k);
            if let Ok(val) = HeaderValue::from_str(v) {
                headers.insert(name, val);
            }
        };

        insert_str("x-acidex-client-name", &h.client.name);
        insert_str("x-acidex-client-version", &h.client.version);
        insert_str("x-acidex-client-platform", &h.client.platform);
        insert_str("x-acidex-client-global-udid", &h.client.global_udid);
        insert_str("x-acidex-os-name", &h.os.name);
        insert_str("x-acidex-os-version", &h.os.version);
        insert_str("x-acidex-os-arch", &h.os.arch);
        insert_str("x-acidex-os-platform", &h.os.platform);
        insert_str("x-acidex-system-hostname", &h.system.hostname);
        insert_str("x-acidex-system-vendor", &h.system.hardware_vendor);
        insert_str("x-acidex-system-model", &h.system.hardware_model);
        insert_str("x-acidex-system-serial", &h.system.hardware_serial);
    }
}

#[derive(Debug, Clone, Default)]
pub struct NoopPostureProvider;

impl PostureProvider for NoopPostureProvider {
    fn handle_stale_posture(&self, proxy_status: &str) -> Result<()> {
        tracing::warn!("Received StalePostureAlert from proxy: {}", proxy_status);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NoopProxyAuthProvider;

impl ProxyAuthProvider for NoopProxyAuthProvider {
    fn handle_407(&self, target: &str) -> Result<Option<HeaderValue>> {
        tracing::warn!("Proxy authentication required (407) for target: {}", target);
        Ok(None)
    }
}
