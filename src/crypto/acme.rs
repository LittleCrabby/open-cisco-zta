use crate::crypto::dpop::DpopSigner;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeOrder {
    pub status: String,
    #[serde(default)]
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeChallenge {
    pub r#type: String,
    pub status: String,
    pub token: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeAuthorization {
    pub status: String,
    #[serde(default)]
    pub challenges: Vec<AcmeChallenge>,
}

pub struct AcmeClient {
    client: reqwest::Client,
    directory_url: String,
    account_key: SigningKey,
    account_url: Option<String>,
    nonce: Option<String>,
    enrollment_id: String,
}

impl AcmeClient {
    pub fn new(directory_url: &str, enrollment_id: &str) -> Self {
        let mut rng = rand::thread_rng();
        let account_key = SigningKey::random(&mut rng);
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            directory_url: directory_url.to_string(),
            account_key,
            account_url: None,
            nonce: None,
            enrollment_id: enrollment_id.to_string(),
        }
    }

    pub async fn fetch_directory(&mut self) -> Result<AcmeDirectory> {
        tracing::info!("Fetching ACME directory from {}", self.directory_url);
        let resp = self
            .client
            .get(&self.directory_url)
            .header("x-request-id", Uuid::new_v4().to_string())
            .header("x-zta-enrollment-id", &self.enrollment_id)
            .send()
            .await?
            .error_for_status()?;

        if let Some(rn) = resp.headers().get("replay-nonce").and_then(|v| v.to_str().ok()) {
            self.nonce = Some(rn.to_string());
        }

        let dir: AcmeDirectory = resp.json().await?;
        Ok(dir)
    }

    pub async fn ensure_nonce(&mut self, new_nonce_url: &str) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }

        let resp = self
            .client
            .head(new_nonce_url)
            .header("x-request-id", Uuid::new_v4().to_string())
            .header("x-zta-enrollment-id", &self.enrollment_id)
            .send()
            .await?
            .error_for_status()?;

        let nonce = resp
            .headers()
            .get("replay-nonce")
            .context("Missing replay-nonce header in ACME response")?
            .to_str()?
            .to_string();

        Ok(nonce)
    }

    pub fn jwk(&self) -> serde_json::Value {
        let verifying_key = self.account_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        })
    }

    pub fn sign_jws(
        &self,
        url: &str,
        nonce: &str,
        payload_bytes: &[u8],
    ) -> Result<serde_json::Value> {
        let protected = if let Some(ref kid) = self.account_url {
            serde_json::json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url
            })
        } else {
            serde_json::json!({
                "alg": "ES256",
                "jwk": self.jwk(),
                "nonce": nonce,
                "url": url
            })
        };

        let prot_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
        let pay_b64 = if payload_bytes.is_empty() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(payload_bytes)
        };

        let signing_input = format!("{}.{}", prot_b64, pay_b64);
        let sig: Signature = self.account_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(serde_json::json!({
            "protected": prot_b64,
            "payload": pay_b64,
            "signature": sig_b64
        }))
    }

    pub async fn send_jws(
        &mut self,
        url: &str,
        new_nonce_url: &str,
        payload_bytes: &[u8],
        extra_headers: &[(&str, String)],
    ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String)> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let nonce = self.ensure_nonce(new_nonce_url).await?;
            let jws = self.sign_jws(url, &nonce, payload_bytes)?;
            let req_id = Uuid::new_v4().to_string();

            let mut req = self
                .client
                .post(url)
                .header("Content-Type", "application/jose+json")
                .header("x-request-id", req_id)
                .header("x-zta-enrollment-id", &self.enrollment_id);

            for (k, v) in extra_headers {
                req = req.header(*k, v.as_str());
            }

            let resp = req.json(&jws).send().await?;
            let status = resp.status();
            let headers = resp.headers().clone();

            if let Some(rn) = headers.get("replay-nonce").and_then(|v| v.to_str().ok()) {
                self.nonce = Some(rn.to_string());
            }

            let text = resp.text().await?;

            if status == reqwest::StatusCode::BAD_REQUEST && text.contains("badNonce") && attempts < 3 {
                tracing::warn!("Received badNonce from ACME, retrying with fresh nonce...");
                self.nonce = None;
                continue;
            }

            return Ok((status, headers, text));
        }
    }

    pub async fn create_account(
        &mut self,
        new_account_url: &str,
        new_nonce_url: &str,
    ) -> Result<String> {
        let payload = serde_json::to_vec(&serde_json::json!({
            "termsOfServiceAgreed": true
        }))?;

        let (status, headers, text) = self
            .send_jws(new_account_url, new_nonce_url, &payload, &[])
            .await?;

        if !status.is_success() && status != reqwest::StatusCode::OK && status != reqwest::StatusCode::CREATED {
            bail!("Failed to create ACME account ({status}): {text}");
        }

        let account_url = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .context("ACME newAccount response missing Location header")?;

        self.account_url = Some(account_url.clone());
        Ok(account_url)
    }

    pub async fn submit_order(
        &mut self,
        new_order_url: &str,
        new_nonce_url: &str,
        san_map: &HashMap<String, String>,
    ) -> Result<(String, AcmeOrder)> {
        // Cisco custom order format requires ZtnaUriList with base64url-encoded JSON map
        let btree: BTreeMap<_, _> = san_map.iter().collect();
        let map_json = serde_json::to_string(&btree)?;
        let val_b64 = URL_SAFE_NO_PAD.encode(map_json.as_bytes());

        let req_body = serde_json::json!({
            "identifiers": [
                {
                    "type": "ZtnaUriList",
                    "value": val_b64
                }
            ]
        });

        let payload = serde_json::to_vec(&req_body)?;
        let (status, headers, text) = self
            .send_jws(new_order_url, new_nonce_url, &payload, &[])
            .await?;

        if !status.is_success() {
            bail!("Failed to submit ACME order ({status}): {text}");
        }

        let order_url = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(new_order_url)
            .to_string();

        let order: AcmeOrder = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse ACME order response: {text}"))?;

        Ok((order_url, order))
    }

    pub async fn fetch_challenge(
        &mut self,
        authz_url: &str,
        new_nonce_url: &str,
    ) -> Result<AcmeChallenge> {
        let (status, _headers, text) = self
            .send_jws(authz_url, new_nonce_url, b"", &[])
            .await?;

        if !status.is_success() {
            bail!("Failed to fetch ACME authorization ({status}): {text}");
        }

        let authz: AcmeAuthorization = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse authorization response: {text}"))?;

        let chall = authz
            .challenges
            .into_iter()
            .find(|c| c.r#type == "ztna-jwt")
            .context("No 'ztna-jwt' challenge found in ACME authorization")?;

        Ok(chall)
    }

    pub async fn respond_challenge(
        &mut self,
        chall_url: &str,
        new_nonce_url: &str,
        auth_jwt: &str,
        dpop: &DpopSigner,
    ) -> Result<()> {
        let dpop_proof = dpop.generate_proof("POST", chall_url, Some(auth_jwt))?;
        let extra_headers = vec![
            ("Authorization", format!("DPoP {}", auth_jwt)),
            ("Dpop", dpop_proof),
        ];

        let payload = b"{}";
        let (status, _headers, text) = self
            .send_jws(chall_url, new_nonce_url, payload, &extra_headers)
            .await?;

        if !status.is_success() {
            bail!("Failed to respond to ACME challenge ({status}): {text}");
        }

        Ok(())
    }

    pub async fn finalize_order(
        &mut self,
        finalize_url: &str,
        new_nonce_url: &str,
        der_csr: &[u8],
    ) -> Result<AcmeOrder> {
        let req_body = serde_json::json!({
            "csr": URL_SAFE_NO_PAD.encode(der_csr)
        });
        let payload = serde_json::to_vec(&req_body)?;

        let (status, _headers, text) = self
            .send_jws(finalize_url, new_nonce_url, &payload, &[])
            .await?;

        if !status.is_success() {
            bail!("Failed to finalize ACME order ({status}): {text}");
        }

        let order: AcmeOrder = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse finalize response: {text}"))?;

        Ok(order)
    }

    pub async fn poll_order_valid(
        &mut self,
        order_url: &str,
        new_nonce_url: &str,
        max_attempts: usize,
    ) -> Result<AcmeOrder> {
        for attempt in 1..=max_attempts {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

            let (status, _headers, text) = self
                .send_jws(order_url, new_nonce_url, b"", &[])
                .await?;

            if !status.is_success() {
                bail!("Failed polling ACME order ({status}): {text}");
            }

            let order: AcmeOrder = serde_json::from_str(&text)
                .with_context(|| format!("Failed to parse polled order: {text}"))?;

            tracing::info!("ACME order poll attempt {}/{}: status={}", attempt, max_attempts, order.status);

            if order.status == "valid" {
                return Ok(order);
            }
            if order.status == "invalid" {
                bail!("ACME order marked as invalid by server: {text}");
            }
        }

        bail!("Timed out waiting for ACME order status to become 'valid'");
    }

    pub async fn download_certificate(
        &mut self,
        cert_url: &str,
        new_nonce_url: &str,
    ) -> Result<String> {
        let extra_headers = vec![
            ("Accept", "application/pem-certificate-chain".to_string()),
        ];

        let (status, _headers, text) = self
            .send_jws(cert_url, new_nonce_url, b"", &extra_headers)
            .await?;

        if status.is_success() && text.contains("BEGIN CERTIFICATE") {
            return Ok(text);
        }

        // Fallback: direct GET request with Accept header
        let resp = self
            .client
            .get(cert_url)
            .header("Accept", "application/pem-certificate-chain")
            .header("x-request-id", Uuid::new_v4().to_string())
            .header("x-zta-enrollment-id", &self.enrollment_id)
            .send()
            .await?;

        let text = resp.text().await?;
        if text.contains("BEGIN CERTIFICATE") {
            Ok(text)
        } else {
            bail!("Failed to download certificate from {cert_url}: {text}")
        }
    }

    pub fn generate_key_and_csr(
        san_uris: &[String],
        device_id: &str,
    ) -> Result<(String, Vec<u8>)> {
        use rcgen::{CertificateParams, DnType, DnValue, KeyPair, SanType};

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let private_key_pem = key_pair.serialize_pem();

        let mut params = CertificateParams::default();
        params.distinguished_name.push(
            DnType::CommonName,
            DnValue::Utf8String(format!("urn:cisco:sse:ztna:deviceid:{}", device_id)),
        );

        for uri in san_uris {
            let ia5 = rcgen::Ia5String::try_from(uri.as_str())
                .map_err(|e| anyhow::anyhow!("Invalid IA5String URI {}: {:?}", uri, e))?;
            params.subject_alt_names.push(SanType::URI(ia5));
        }

        let csr = params.serialize_request(&key_pair)?;
        let der = csr.der().to_vec();

        Ok((private_key_pem, der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_and_csr() {
        let san_uris = vec![
            "urn:cisco:sse:dhaid:nil".to_string(),
            "urn:cisco:sse:orgid:12345".to_string(),
            "urn:cisco:sse:userid:user@example.com".to_string(),
            "urn:cisco:sse:username:user@example.com".to_string(),
            "urn:cisco:sse:ztna:deviceid:device-test-123".to_string(),
        ];
        let (key_pem, der_csr) = AcmeClient::generate_key_and_csr(&san_uris, "device-test-123").unwrap();

        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!der_csr.is_empty());
    }

    #[test]
    fn test_jws_signing_and_post_as_get() {
        let acme = AcmeClient::new("https://example.com/acme/directory", "test-dev-1");
        
        // POST-as-GET (empty payload)
        let jws_empty = acme.sign_jws("https://example.com/authz/1", "nonce-123", b"").unwrap();
        assert_eq!(jws_empty["payload"].as_str().unwrap(), "");
        assert!(!jws_empty["protected"].as_str().unwrap().is_empty());
        assert!(!jws_empty["signature"].as_str().unwrap().is_empty());

        // Regular POST with payload
        let payload = br#"{"termsOfServiceAgreed":true}"#;
        let jws_payload = acme.sign_jws("https://example.com/newAccount", "nonce-456", payload).unwrap();
        assert!(!jws_payload["payload"].as_str().unwrap().is_empty());
    }
}
