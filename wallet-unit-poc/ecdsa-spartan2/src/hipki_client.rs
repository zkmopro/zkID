//! Client for the HiPKI LocalSignServer.
//!
//! Calls the local HiPKI server to fetch certificate chains and sign data
//! using the Taiwan Citizen Digital Certificate (自然人憑證).

use crate::circuits::types::{CardSignResponse, Pkcs11InfoResponse};
use std::error::Error;

const DEFAULT_SERVER_URL: &str = "http://localhost:61161";

/// Fetch the full certificate chain from HiPKI `/pkcs11info?withcert=true`.
///
/// Returns the parsed response containing Root CA, intermediate CA (MOICA),
/// and user certificates from the smart card.
pub fn fetch_pkcs11info(server_url: &str) -> Result<Pkcs11InfoResponse, Box<dyn Error>> {
    let url = format!(
        "{}/pkcs11info?withcert=true",
        server_url.trim_end_matches('/')
    );

    let resp: Pkcs11InfoResponse = ureq::get(&url).call()?.into_json()?;
    Ok(resp)
}

/// Sign TBS data using the card's private key via HiPKI `/sign` API.
///
/// Uses `signatureType: "PKCS1"` to get a raw RSA PKCS#1 v1.5 signature
/// (not CMS-wrapped), which is what the circuit expects.
///
/// # Arguments
/// * `server_url` - HiPKI server URL (e.g., `http://localhost:61161`)
/// * `tbs` - The To-Be-Signed data string
/// * `pin` - The card PIN (6-8 digits)
pub fn sign_tbs(server_url: &str, tbs: &str, pin: &str) -> Result<CardSignResponse, Box<dyn Error>> {
    let url = format!("{}/sign", server_url.trim_end_matches('/'));

    let tbs_package = serde_json::json!({
        "tbs": tbs,
        "pin": pin,
        "hashAlgorithm": "SHA256",
        "signatureType": "PKCS1"
    });

    let resp: CardSignResponse = ureq::post(&url)
        .send_form(&[("tbsPackage", &tbs_package.to_string())])?
        .into_json()?;

    Ok(resp)
}

/// Returns the default HiPKI server URL.
pub fn default_server_url() -> &'static str {
    DEFAULT_SERVER_URL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_url() {
        assert_eq!(default_server_url(), "http://localhost:61161");
    }

    #[test]
    fn test_tbs_package_serialization() {
        let pkg = serde_json::json!({
            "tbs": "123456",
            "pin": "830929",
            "hashAlgorithm": "SHA256",
            "signatureType": "PKCS1"
        });
        let s = pkg.to_string();
        assert!(s.contains("\"tbs\":\"123456\""));
        assert!(s.contains("\"signatureType\":\"PKCS1\""));
    }

    #[test]
    #[ignore] // requires live HiPKI server + card
    fn test_fetch_pkcs11info_live() {
        let resp = fetch_pkcs11info(DEFAULT_SERVER_URL).unwrap();
        assert!(!resp.slots.is_empty());
    }
}
