use crate::crypto::acme::AcmeClient;
use crate::crypto::dpop::DpopSigner;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollInitResponse {
    #[serde(rename = "sso-begin-url")]
    pub sso_begin_url: Option<String>,
    #[serde(rename = "sso-end-url")]
    pub sso_end_url: Option<String>,
    #[serde(rename = "jwt-location")]
    pub jwt_location: Option<String>,
    #[serde(rename = "dha_base_url")]
    pub dha_base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoClaims {
    pub sub: Option<String>,
    pub username: Option<String>,
    pub user_id: Option<String>,
    pub origin_id: Option<String>,
    pub duo_device_id: Option<String>,
    pub ztna_device_id: Option<String>,
    pub dha_base_url: Option<String>,
    pub dev_reg_url: Option<String>,
    pub dha_reg_url: Option<String>,
    pub acme_dir_url: Option<String>,
    pub config_sync_url: Option<String>,
    #[serde(default)]
    pub identifiers: HashMap<String, String>,
}

pub struct EnrollmentService {
    bootstrap_url: String,
}

impl Default for EnrollmentService {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrollmentService {
    pub fn new() -> Self {
        Self {
            bootstrap_url: "https://enroll.ztna.sse.cisco.com/enrollInit".to_string(),
        }
    }

    pub async fn bootstrap(&self, dpop: &DpopSigner) -> Result<EnrollInitResponse> {
        let payload = serde_json::json!({
            "type": "CiscoSecureAccess",
            "choice_id": "cisco-secure-access/default"
        });
        let body_bytes = serde_json::to_vec(&payload)?;

        let proof = dpop.generate_proof_with_body(
            "POST",
            &self.bootstrap_url,
            None,
            Some(&body_bytes),
        )?;

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.bootstrap_url)
            .header(CONTENT_TYPE, "application/json")
            .header("Dpop", proof)
            .body(body_bytes)
            .send()
            .await?
            .error_for_status()?;

        let init: EnrollInitResponse = resp.json().await?;
        Ok(init)
    }

    pub fn parse_sso_jwt(jwt_str: &str) -> Result<SsoClaims> {
        let trimmed = jwt_str.trim().trim_matches('"');
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() < 2 {
            bail!("Invalid JWT format: expected at least 2 dot-separated segments");
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .or_else(|_| URL_SAFE_NO_PAD.decode(format!("{}=", parts[1])))
            .or_else(|_| URL_SAFE_NO_PAD.decode(format!("{}==", parts[1])))
            .context("Failed to base64url-decode JWT payload")?;

        let value: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .context("JWT payload is not valid JSON")?;

        let normalize_url = |s: &str| -> String {
            if s.contains("://") {
                s.to_string()
            } else {
                format!("https://{}", s)
            }
        };

        let sub = value.get("sub").and_then(|v| v.as_str()).map(String::from);
        let username = value.get("username").and_then(|v| v.as_str()).map(String::from);
        let dev_reg_url = value
            .get("dev_reg_url")
            .and_then(|v| v.as_str())
            .map(normalize_url);
        let dha_reg_url = value
            .get("dha_reg_url")
            .and_then(|v| v.as_str())
            .map(normalize_url);
        let acme_dir_url = value
            .get("acme_dir_url")
            .and_then(|v| v.as_str())
            .map(normalize_url);
        let config_sync_url = value
            .get("config_sync_url")
            .and_then(|v| v.as_str())
            .map(normalize_url);

        let mut identifiers = HashMap::new();
        if let Some(map) = value.get("identifiers").and_then(|v| v.as_object()) {
            for (k, v) in map {
                if let Some(val_str) = v.as_str() {
                    identifiers.insert(k.clone(), val_str.to_string());
                }
            }
        }

        let user_id = identifiers
            .get("urn:cisco:sse:userid")
            .cloned()
            .or_else(|| value.get("oid_user").and_then(|v| v.as_str()).map(String::from))
            .or_else(|| value.get("user_id").and_then(|v| v.as_str()).map(String::from))
            .or_else(|| value.get("uid").and_then(|v| v.as_str()).map(String::from));

        let origin_id = identifiers
            .get("urn:cisco:sse:ztna:originid")
            .cloned()
            .or_else(|| value.get("origin_id").and_then(|v| v.as_str()).map(String::from));

        let ztna_device_id = identifiers
            .get("urn:cisco:sse:ztna:deviceid")
            .cloned()
            .or_else(|| value.get("ztna_device_id").and_then(|v| v.as_str()).map(String::from));

        let duo_device_id = value
            .get("duo_device_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let dha_base_url = value
            .get("dha_base_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(SsoClaims {
            sub,
            username,
            user_id,
            origin_id,
            duo_device_id,
            ztna_device_id,
            dha_base_url,
            dev_reg_url,
            dha_reg_url,
            acme_dir_url,
            config_sync_url,
            identifiers,
        })
    }

    pub async fn register_device(
        &self,
        dev_reg_url: &str,
        sso_jwt: &str,
        dpop: &DpopSigner,
        client_generated_id: &str,
    ) -> Result<(String, String)> {
        let body_json = serde_json::json!({
            "client_generated_id": client_generated_id,
            "module_type_id": 57,
            "module_independent_device_id": client_generated_id,
        });

        let body_bytes = serde_json::to_vec(&body_json)?;

        // Cisco Umbrella API requires DPoP proof with ath (SSO JWT hash) and body_hash (JSON body hash)
        let dpop_proof = dpop.generate_proof_with_body(
            "POST",
            dev_reg_url,
            Some(sso_jwt),
            Some(&body_bytes),
        )?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        // Cisco Secure Client sends composite Authorization header: DPOP <JWT>, Bearer <JWT>
        let auth_header = format!("DPOP {}, Bearer {}", sso_jwt, sso_jwt);

        let resp = client
            .post(dev_reg_url)
            .header(AUTHORIZATION, &auth_header)
            .header("Dpop", &dpop_proof)
            .header(CONTENT_TYPE, "application/json")
            .body(body_bytes)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;

        if !status.is_success() {
            tracing::error!("Device registration failed with status {}: {}", status, text);
            bail!("Device registration rejected with HTTP {}: {}", status, text);
        }

        let body: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or(serde_json::Value::Null);

        let dr_jwt = body
            .get("DR_JWT")
            .or_else(|| body.get("dr_jwt"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let assigned_device_id = body
            .get("ztna_device_id")
            .or_else(|| body.get("device_id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| client_generated_id.to_string());

        let effective_jwt = if dr_jwt.is_empty() {
            tracing::info!("DR_JWT not returned separately, continuing with SSO JWT");
            sso_jwt.to_string()
        } else {
            dr_jwt.to_string()
        };

        Ok((effective_jwt, assigned_device_id))
    }

    /// Performs Cisco DHA registration (`actionSendDhaRegistrationRequest`), exchanging
    /// `SSO_JWT` + `DR_JWT` + device posture (`acidex`) for `DHA_ENROLL_DONE_JWT`.
    /// `DHA_ENROLL_DONE_JWT` contains the authoritative ACME `identifiers` map and serves
    /// as the bearer/DPoP token for responding to the ACME `ztna-jwt` challenge.
    pub async fn register_dha(
        &self,
        dha_reg_url: &str,
        sso_jwt: &str,
        dr_jwt: &str,
        dpop: &DpopSigner,
        os_profile: crate::plugins::OsProfile,
    ) -> Result<(String, SsoClaims)> {
        let ephemeral = DpopSigner::new_random();
        let dha_enroll_pubkey = ephemeral.public_key_pem()?;
        let acidex = crate::plugins::acidex::AcidexPayload::with_profile(os_profile).acidex;

        let body_json = serde_json::json!({
            "acidex": acidex,
            "dha_enroll_pubkey": dha_enroll_pubkey,
        });
        let body_bytes = serde_json::to_vec(&body_json)?;

        let dpop_proof = dpop.generate_dha_proof(
            "POST",
            dha_reg_url,
            sso_jwt,
            dr_jwt,
            &body_bytes,
        )?;

        let auth_header = format!("DPOP {}, DPOP {}", sso_jwt, dr_jwt);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        let resp = client
            .post(dha_reg_url)
            .header(AUTHORIZATION, &auth_header)
            .header("Dpop", &dpop_proof)
            .header(CONTENT_TYPE, "application/json")
            .header("x-request-id", uuid::Uuid::new_v4().to_string())
            .body(body_bytes)
            .send()
            .await?;

        let status = resp.status();
        let jwt_type = resp
            .headers()
            .get("SSE-Enroll-JWT-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = resp.text().await?;

        if !status.is_success() {
            tracing::error!("DHA registration failed with status {}: {}", status, text);
            bail!("DHA registration rejected with HTTP {}: {}", status, text);
        }

        tracing::info!("DHA registration succeeded (SSE-Enroll-JWT-Type: {})", jwt_type);

        let trimmed = text.trim().trim_matches('"');
        let dha_jwt = if trimmed.starts_with("eyJ") {
            trimmed.to_string()
        } else if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(s) = json_val.as_str() {
                s.to_string()
            } else if let Some(obj) = json_val.as_object() {
                obj.values()
                    .find_map(|v| v.as_str().filter(|s| s.starts_with("eyJ")))
                    .map(String::from)
                    .unwrap_or_else(|| trimmed.to_string())
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };

        let dha_claims = Self::parse_sso_jwt(&dha_jwt)
            .context("Failed to parse DHA_ENROLL_DONE_JWT claims")?;

        Ok((dha_jwt, dha_claims))
    }

    pub async fn issue_certificate(
        &self,
        acme_dir_url: &str,
        device_id: &str,
        san_map: &HashMap<String, String>,
        auth_jwt: &str,
        dpop: &DpopSigner,
        output_dir: &Path,
    ) -> Result<()> {
        let mut san_uris: Vec<String> = san_map.iter().map(|(k, v)| format!("{}:{}", k, v)).collect();
        san_uris.sort();

        tracing::info!("Generating client private key and CSR with SANs: {:?}", san_uris);
        let (priv_key_pem, der_csr) = AcmeClient::generate_key_and_csr(&san_uris, device_id)?;

        let mut acme = AcmeClient::new(acme_dir_url, device_id);

        println!("  [ACME 1/5] Fetching directory from Cisco ACME CA...");
        let dir = acme
            .fetch_directory()
            .await
            .context("Failed to fetch ACME directory")?;

        println!("  [ACME 2/5] Registering ACME account with Cisco CA...");
        let account_url = acme
            .create_account(&dir.new_account, &dir.new_nonce)
            .await
            .context("Failed to create ACME account")?;
        tracing::info!("Registered ACME account: {}", account_url);

        println!("  [ACME 3/5] Submitting certificate order (ZtnaUriList)...");
        let (order_url, order) = acme
            .submit_order(&dir.new_order, &dir.new_nonce, san_map)
            .await
            .context("Failed to submit ACME order")?;

        println!("  [ACME 4/5] Answering ZTNA challenge with DPoP proof...");
        for authz_url in &order.authorizations {
            let chall = acme
                .fetch_challenge(authz_url, &dir.new_nonce)
                .await
                .context("Failed to fetch ACME authorization challenge")?;

            acme.respond_challenge(&chall.url, &dir.new_nonce, auth_jwt, dpop)
                .await
                .context("Failed to respond to ACME challenge")?;
        }

        println!("  [ACME 5/5] Finalizing order and downloading signed mTLS certificate chain...");
        let finalized = acme
            .finalize_order(&order.finalize, &dir.new_nonce, &der_csr)
            .await
            .context("Failed to finalize ACME order")?;

        let valid_order = if finalized.status == "valid" && finalized.certificate.is_some() {
            finalized
        } else {
            acme.poll_order_valid(&order_url, &dir.new_nonce, 15)
                .await
                .context("Failed waiting for ACME order validation")?
        };

        let cert_url = valid_order
            .certificate
            .context("ACME order has no certificate URL")?;

        let cert_chain_pem = acme
            .download_certificate(&cert_url, &dir.new_nonce)
            .await
            .context("Failed to download issued certificate chain")?;

        let cert_file = output_dir.join("client_cert.pem");
        let key_file = output_dir.join("client_key.pem");

        fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory {:?}", output_dir))?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_file)
                .with_context(|| format!("Failed to open private key file {:?}", key_file))?;
            f.write_all(priv_key_pem.as_bytes())
                .with_context(|| format!("Failed to write private key to {:?}", key_file))?;
            let _ = fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600));
        }

        #[cfg(not(unix))]
        {
            fs::write(&key_file, priv_key_pem.as_bytes())
                .with_context(|| format!("Failed to write private key to {:?}", key_file))?;
        }

        fs::write(&cert_file, cert_chain_pem.as_bytes())
            .with_context(|| format!("Failed to write certificate chain to {:?}", cert_file))?;

        println!("  [+] Successfully issued genuine Cisco client mTLS certificate!");
        tracing::info!("Saved genuine client certificate chain to {:?}", cert_file);
        tracing::info!("Saved client private key to {:?}", key_file);

        Ok(())
    }
}
