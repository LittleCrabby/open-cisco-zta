use crate::config::{ConfigManager, ZtnaConfig, ZtnaConfigWrapper};
use crate::crypto::{create_ssl_connector, TlsConfig};
use crate::plugins::{AcidexPayload, OsProfile};
use anyhow::{bail, Context, Result};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;
use uuid::Uuid;

#[derive(Debug)]
pub enum SyncResult {
    NotModified { etag: String, interval: Option<u32> },
    Updated { etag: String, interval: Option<u32>, new_config: ZtnaConfig },
}

pub struct ConfigSync {
    config_mgr: ConfigManager,
    os_profile_override: Option<OsProfile>,
}

impl ConfigSync {
    pub fn new(config_mgr: ConfigManager) -> Self {
        Self {
            config_mgr,
            os_profile_override: None,
        }
    }

    pub fn with_os_profile(config_mgr: ConfigManager, os_profile: Option<OsProfile>) -> Self {
        Self {
            config_mgr,
            os_profile_override: os_profile,
        }
    }

    pub async fn sync_once(&self) -> Result<SyncResult> {
        let enrollment = self.config_mgr.load_enrollment()
            .context("Failed to load enrollment state for ConfigSync")?;

        let sync_url = Url::parse(&enrollment.config_sync_url)
            .with_context(|| format!("Invalid config_sync_url: {}", enrollment.config_sync_url))?;

        let host = sync_url.host_str().context("Missing host in config_sync_url")?;
        let port = sync_url.port().unwrap_or(443);
        let path_and_query = format!(
            "{}{}",
            sync_url.path(),
            sync_url.query().map(|q| format!("?{q}")).unwrap_or_default()
        );

        let cert_path = self.config_mgr.cert_path();
        let key_path = self.config_mgr.key_path();

        let cert_opt = if cert_path.exists() { Some(cert_path.as_path()) } else { None };
        let key_opt = if key_path.exists() { Some(key_path.as_path()) } else { None };

        let tls_cfg = TlsConfig::for_http1(cert_opt, key_opt);
        let connector = create_ssl_connector(&tls_cfg)?;

        tracing::info!("Connecting to ConfigSync server {}:{} (mTLS)", host, port);
        let tcp = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("Failed to connect to {host}:{port}"))?;

        let ssl = connector
            .configure()?
            .into_ssl(host)
            .context("Failed to configure SSL for host")?;

        let mut tls_stream = tokio_openssl::SslStream::new(ssl, tcp)?;
        Pin::new(&mut tls_stream)
            .connect()
            .await
            .context("TLS handshake failed during ConfigSync")?;

        let os_profile = self.os_profile_override.unwrap_or_else(|| {
            enrollment
                .os_profile
                .as_deref()
                .and_then(|p| p.parse::<OsProfile>().ok())
                .unwrap_or_default()
        });
        let acidex = AcidexPayload::with_profile(os_profile);
        let body_bytes = serde_json::to_vec(&acidex)?;
        let request_id = Uuid::new_v4().to_string();
        let enrollment_id = if !enrollment.ztna_device_id.is_empty() {
            enrollment.ztna_device_id.as_str()
        } else {
            "00000000-0000-0000-0000-000000000000"
        };

        let mut req = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/json;charset=utf-8, application/json\r\n\
             Content-Type: application/json;charset=utf-8, application/json\r\n\
             Content-Length: {}\r\n\
             x-request-id: {}\r\n\
             x-zta-accept-config-schema-version: 2, 1\r\n\
             x-zta-enrollment-id: {}\r\n\
             Connection: close\r\n",
            path_and_query,
            host,
            body_bytes.len(),
            request_id,
            enrollment_id
        );

        if let Some(ref etag) = enrollment.config_etag {
            req.push_str(&format!("If-None-Match: {}\r\n", etag));
        }
        req.push_str("\r\n");

        tls_stream.write_all(req.as_bytes()).await?;
        tls_stream.write_all(&body_bytes).await?;
        tls_stream.flush().await?;

        // Read response
        let mut response_bytes = Vec::new();
        tls_stream.read_to_end(&mut response_bytes).await?;

        let parsed = parse_http1_response(&response_bytes)?;
        tracing::info!("ConfigSync response: {}", parsed.status_line);

        match parsed.status_code {
            304 => {
                let etag_val = parsed.etag.or(enrollment.config_etag).unwrap_or_default();
                tracing::info!("Config not modified (ETag: {})", etag_val);
                Ok(SyncResult::NotModified {
                    etag: etag_val,
                    interval: parsed.interval,
                })
            }
            200 => {
                let etag_val = parsed.etag.unwrap_or_default();
                let wrapper: ZtnaConfigWrapper = serde_json::from_slice(&parsed.body)
                    .with_context(|| "Failed to parse new ZtnaConfig from ConfigSync response")?;

                // Save updated config
                self.config_mgr.save_ztna_config(&wrapper.ztna_config)?;

                // Update enrollment state
                let mut updated_enrollment = enrollment;
                updated_enrollment.config_etag = Some(etag_val.clone());
                if let Some(int) = parsed.interval {
                    updated_enrollment.config_sync_interval = Some(int.to_string());
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
                    .to_string();
                updated_enrollment.last_config_sync_success_time = Some(now);
                self.config_mgr.save_enrollment(&updated_enrollment)?;

                tracing::info!("Successfully updated ZtnaConfig (ETag: {})", etag_val);
                Ok(SyncResult::Updated {
                    etag: etag_val,
                    interval: parsed.interval,
                    new_config: wrapper.ztna_config,
                })
            }
            other => {
                let body_str = String::from_utf8_lossy(&parsed.body);
                bail!("ConfigSync failed with HTTP status {}: {}", other, body_str);
            }
        }
    }
}

struct ParsedHttp1Response {
    status_line: String,
    status_code: u16,
    etag: Option<String>,
    interval: Option<u32>,
    body: Vec<u8>,
}

fn parse_http1_response(raw: &[u8]) -> Result<ParsedHttp1Response> {
    let sep = b"\r\n\r\n";
    let header_end = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .unwrap_or(raw.len());

    let header_part = String::from_utf8_lossy(&raw[..header_end]);
    let raw_body = if header_end + sep.len() <= raw.len() {
        &raw[header_end + sep.len()..]
    } else {
        &[][..]
    };

    let status_line = header_part.lines().next().unwrap_or("").to_string();
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut etag = None;
    let mut interval = None;
    let mut is_chunked = false;

    for line in header_part.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_lowercase();
            let v = v.trim();
            if k == "etag" {
                etag = Some(v.trim_matches('"').to_string());
            } else if k == "sync-interval-minute" {
                interval = v.parse::<u32>().ok();
            } else if k == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                is_chunked = true;
            }
        }
    }

    let body = if is_chunked {
        decode_chunked_body(raw_body)?
    } else {
        raw_body.to_vec()
    };

    Ok(ParsedHttp1Response {
        status_line,
        status_code,
        etag,
        interval,
        body,
    })
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let line_end = match input.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_line = std::str::from_utf8(&input[..line_end])
            .context("Invalid UTF-8 in chunk size line")?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_size = usize::from_str_radix(size_line, 16)
            .with_context(|| format!("Invalid hex chunk size: '{}'", size_line))?;

        input = &input[line_end + 2..];
        if chunk_size == 0 {
            break;
        }
        if input.len() < chunk_size {
            bail!(
                "Truncated HTTP chunk: expected {} bytes, got {}",
                chunk_size,
                input.len()
            );
        }
        out.extend_from_slice(&input[..chunk_size]);
        input = &input[chunk_size..];
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http1_response_chunked() {
        let json_part1 = br#"{"ztnaConfig":{"resource_configs":["#;
        let json_part2 = br#"]}}"#;
        let raw_resp = format!(
            "HTTP/1.1 200 OK\r\n\
             ETag: \"abc-123\"\r\n\
             Sync-Interval-Minute: 15\r\n\
             Transfer-Encoding: chunked\r\n\r\n\
             {:x}\r\n{}\r\n\
             {:x}\r\n{}\r\n\
             0\r\n\r\n",
            json_part1.len(),
            std::str::from_utf8(json_part1).unwrap(),
            json_part2.len(),
            std::str::from_utf8(json_part2).unwrap(),
        );

        let parsed = parse_http1_response(raw_resp.as_bytes()).unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.etag.as_deref(), Some("abc-123"));
        assert_eq!(parsed.interval, Some(15));
        let wrapper: ZtnaConfigWrapper = serde_json::from_slice(&parsed.body).unwrap();
        assert!(wrapper.ztna_config.resource_configs.is_empty());
    }
}
