//! license-core: License validation (Ed25519). DEV vs PROD key by env only; no bypass.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// License payload (tenant_id mandatory).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct License {
    pub license_id: String,
    pub tenant_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub grace_days: u64,
    #[serde(default)]
    pub platform_version: Option<String>,
}

/// Signed license file format. Signature covers `signed_payload_utf8` byte-for-byte.
#[derive(Deserialize)]
pub struct SignedLicenseFile {
    pub payload: License,
    /// Exact UTF-8 payload that was signed (deterministic for verification).
    pub signed_payload_utf8: String,
    pub signature_base64: String,
}

/// Canonical JSON serialization for license payload.
/// Uses deterministic field order from the struct definition and no extra whitespace.
pub fn serialize_license_canonical(payload: &License) -> Result<String, String> {
    serde_json::to_string(payload).map_err(|e| format!("Canonical serialization failed: {}", e))
}

/// Select which public key to use. DEV key only when LICENSE_DEV_MODE=true.
/// No key is compiled in; both come from environment at runtime.
fn public_key_base64() -> Result<String, String> {
    let dev_mode = std::env::var("LICENSE_DEV_MODE")
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if dev_mode {
        std::env::var("DEV_PUBLIC_KEY").map_err(|_| {
            "LICENSE_DEV_MODE is set but DEV_PUBLIC_KEY is not set. Run the dev license generator and set DEV_PUBLIC_KEY.".to_string()
        })
    } else {
        std::env::var("PROD_PUBLIC_KEY").map_err(|_| {
            "PROD_PUBLIC_KEY is not set. Production requires a valid production public key."
                .to_string()
        })
    }
}

/// Verify Ed25519 signature. Public API for Ed25519 signature validation.
/// Message and signature_base64 must match the signed payload; public_key_base64 is the Ed25519 public key (32 bytes, base64).
pub fn verify_ed25519_signature(
    message: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), String> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| format!("Invalid signature base64: {}", e))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Signature must be 64 bytes")?;
    let signature = Signature::from_bytes(&sig);

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| format!("Invalid public key base64: {}", e))?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Public key must be 32 bytes")?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_arr).map_err(|e| format!("Invalid public key: {}", e))?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| "Signature verification failed".to_string())?;
    Ok(())
}

/// Validate that a version string satisfies platform SemVer requirements.
pub fn validate_semver(version: &str, required: &str) -> Result<(), String> {
    let v = semver::Version::parse(version).map_err(|e| e.to_string())?;
    let req = semver::VersionReq::parse(required).map_err(|e| e.to_string())?;
    if req.matches(&v) {
        Ok(())
    } else {
        Err(format!(
            "Version {} does not satisfy requirement {}",
            version, required
        ))
    }
}

/// Validate license: always verifies Ed25519 signature; only the public key source (DEV vs PROD) changes by env.
/// Must be called before service DB init / start. No bypass.
pub fn validate_license() -> Result<(), String> {
    let path = std::env::var("LICENSE_PATH").unwrap_or_else(|_| "license.json".to_string());
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read license file {}: {}", path, e))?;
    let signed: SignedLicenseFile =
        serde_json::from_str(&contents).map_err(|e| format!("Invalid license format: {}", e))?;

    // Canonicalization guard: payload must match canonical serialization exactly.
    let canonical = serialize_license_canonical(&signed.payload)?;
    if canonical != signed.signed_payload_utf8 {
        return Err(
            "signed_payload_utf8 does not match canonical payload serialization".to_string(),
        );
    }

    let public_key_b64 = public_key_base64()?;
    verify_ed25519_signature(
        signed.signed_payload_utf8.as_bytes(),
        &signed.signature_base64,
        &public_key_b64,
    )?;

    if let Some(ref req) = signed.payload.platform_version {
        validate_semver("1.0.0", req)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample_license() -> License {
        License {
            license_id: "LIC-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            grace_days: 30,
            platform_version: Some(">=1.0.0".to_string()),
        }
    }

    #[test]
    fn test_validate_semver() {
        assert!(validate_semver("1.2.3", ">=1.0.0").is_ok());
        assert!(validate_semver("0.9.0", ">=1.0.0").is_err());
        // exact match
        assert!(validate_semver("1.0.0", "1.0.0").is_ok());
        assert!(validate_semver("1.0.1", "=1.0.0").is_err());
        // caret and tilde ranges
        assert!(validate_semver("1.2.3", "^1.0.0").is_ok());
        assert!(validate_semver("2.0.0", "^1.0.0").is_err());
        assert!(validate_semver("1.2.3", "~1.2.0").is_ok());
        assert!(validate_semver("1.3.0", "~1.2.0").is_err());
        // prerelease handling: must match requirement including pre
        assert!(validate_semver("1.2.3-alpha.1", ">=1.2.3-alpha.1, <1.2.3").is_ok());
        assert!(validate_semver("1.2.3-alpha.1", ">=1.2.3").is_err());
        // invalid inputs surface errors
        assert!(validate_semver("not-a-version", ">=1.0.0").is_err());
        assert!(validate_semver("1.0.0", "not-a-req").is_err());
    }

    #[test]
    fn test_canonical_serialization_is_deterministic() {
        let license = sample_license();
        let a = serialize_license_canonical(&license).expect("serialize a");
        let b = serialize_license_canonical(&license).expect("serialize b");
        assert_eq!(a, b);
    }

    #[test]
    fn test_verify_ed25519_signature_accepts_valid() {
        use ed25519_dalek::{Signer, SigningKey};
        let msg = b"test message";
        let signing_key = SigningKey::from_bytes(&ed25519_dalek::SecretKey::from([1u8; 32]));
        let sig = signing_key.sign(msg);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        assert!(verify_ed25519_signature(msg, &sig_b64, &pub_b64).is_ok());
    }

    #[test]
    fn test_verify_ed25519_signature_rejects_tampered() {
        let msg = b"test message";
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(verify_ed25519_signature(msg, &sig_b64, &pub_b64).is_err());
    }
}
