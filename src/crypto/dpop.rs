use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkEcKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: JwkEcKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elb_ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr_ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
}

pub struct DpopSigner {
    signing_key: SigningKey,
    jwk: JwkEcKey,
}

impl DpopSigner {
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::random(&mut rng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x_bytes = encoded_point.x().expect("x coordinate missing");
        let y_bytes = encoded_point.y().expect("y coordinate missing");

        let jwk = JwkEcKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: URL_SAFE_NO_PAD.encode(x_bytes),
            y: URL_SAFE_NO_PAD.encode(y_bytes),
        };

        Self { signing_key, jwk }
    }

    pub fn jwk(&self) -> &JwkEcKey {
        &self.jwk
    }

    pub fn public_key_pem(&self) -> Result<String> {
        let pem = self
            .signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)?;
        Ok(pem)
    }

    /// RFC 7638 JWK Thumbprint (SHA-256 base64url encoded)
    pub fn jkt(&self) -> String {
        // Canonical JSON for EC P-256: sorted keys: crv, kty, x, y
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            self.jwk.crv, self.jwk.kty, self.jwk.x, self.jwk.y
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    pub fn generate_proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
    ) -> Result<String> {
        self.generate_proof_with_body(method, url, access_token, None)
    }

    pub fn generate_proof_with_body(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<String> {
        let header = DpopHeader {
            typ: "dpop+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: self.jwk.clone(),
        };

        // Strip query string and fragment as per RFC 9449
        let clean_url = url.split(&['?', '#'][..]).next().unwrap_or(url);

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let ath = access_token.map(|tok| {
            let mut hasher = Sha256::new();
            hasher.update(tok.as_bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let body_hash = body.map(|b| {
            let mut hasher = Sha256::new();
            hasher.update(b);
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let claims = DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: clean_url.to_string(),
            iat: now,
            ath,
            elb_ath: None,
            dr_ath: None,
            body_hash,
        };

        self.sign_claims(&header, &claims)
    }

    /// Generates a DPoP proof for Cisco DHA registration (`actionSendDhaRegistrationRequest`),
    /// which requires both `elb_ath` (SHA-256 of SSO JWT) and `dr_ath` (SHA-256 of DR JWT)
    /// in addition to `body_hash`.
    pub fn generate_dha_proof(
        &self,
        method: &str,
        url: &str,
        sso_jwt: &str,
        dr_jwt: &str,
        body: &[u8],
    ) -> Result<String> {
        let header = DpopHeader {
            typ: "dpop+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: self.jwk.clone(),
        };

        let clean_url = url.split(&['?', '#'][..]).next().unwrap_or(url);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let elb_ath = {
            let mut hasher = Sha256::new();
            hasher.update(sso_jwt.as_bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        };

        let dr_ath = {
            let mut hasher = Sha256::new();
            hasher.update(dr_jwt.as_bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        };

        let body_hash = {
            let mut hasher = Sha256::new();
            hasher.update(body);
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        };

        let claims = DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: clean_url.to_string(),
            iat: now,
            ath: None,
            elb_ath: Some(elb_ath),
            dr_ath: Some(dr_ath),
            body_hash: Some(body_hash),
        };

        self.sign_claims(&header, &claims)
    }

    fn sign_claims(&self, header: &DpopHeader, claims: &DpopClaims) -> Result<String> {
        let header_json = serde_json::to_string(header)?;
        let claims_json = serde_json::to_string(claims)?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());

        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, sig_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpop_proof_generation() {
        let signer = DpopSigner::new_random();
        let proof = signer
            .generate_proof(
                "POST",
                "https://devices.api.umbrella.com/deployments/v2/ztna?foo=bar",
                Some("mock_access_token_123"),
            )
            .expect("Should generate DPoP proof");

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "DPoP proof must be a 3-part JWS compact token");

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: DpopHeader = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header.typ, "dpop+jwt");
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.jwk.kty, "EC");
        assert_eq!(header.jwk.crv, "P-256");

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: DpopClaims = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims.htm, "POST");
        assert_eq!(
            claims.htu,
            "https://devices.api.umbrella.com/deployments/v2/ztna"
        );
        assert!(claims.ath.is_some());
    }
}
