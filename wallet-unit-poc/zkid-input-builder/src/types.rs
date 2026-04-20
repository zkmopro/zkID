//! Serde structs for HiPKI / PKCS#11 API responses and SMT circuit inputs.

use serde::{Deserialize, Serialize};

/// Response from HiPKI `/sign` API with `signatureType: "PKCS1"`.
#[derive(Deserialize)]
pub struct CardSignResponse {
    #[serde(rename = "cardSN")]
    pub card_sn: String,
    pub certb64: String,
    #[serde(rename = "func")]
    _func: String,
    #[serde(rename = "last_error")]
    _last_error: i32,
    #[serde(rename = "ret_code")]
    _ret_code: i32,
    pub signature: String,
    #[serde(rename = "version")]
    _version: String,
}

/// Response from RS4096 sign API (4096-bit issuer CA path).
#[derive(Deserialize)]
pub struct Rs4096SignResponse {
    pub error_code: String,
    pub error_message: String,
    pub result: Rs4096SignResult,
}

#[derive(Deserialize)]
pub struct Rs4096SignResult {
    pub hashed_id_num: String,
    pub signed_response: String,
    pub idp_checksum: String,
    pub cert: String,
}

#[derive(Deserialize, Debug)]
pub struct Pkcs11CertEntry {
    pub certb64: String,
    pub label: String,
    #[serde(default)]
    pub usage: Option<String>,
    #[serde(default)]
    pub sn: Option<String>,
    #[serde(rename = "subjectDN", default)]
    pub subject_dn: Option<String>,
    #[serde(rename = "issuerDN", default)]
    pub issuer_dn: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Pkcs11TokenInfo {
    #[serde(default)]
    pub certs: Vec<Pkcs11CertEntry>,
    #[serde(rename = "serialNumber", default)]
    pub serial_number: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Pkcs11Slot {
    #[serde(default)]
    pub token: Option<Pkcs11TokenInfo>,
}

#[derive(Deserialize, Debug)]
pub struct Pkcs11InfoResponse {
    pub slots: Vec<Pkcs11Slot>,
}

/// Circuit-ready SMT non-membership inputs (all values are decimal strings).
///
/// Derived from the moica-revocation-smt server response; see
/// `ecdsa_spartan2::smt_client::fetch_smt_proof` for the native fetch path
/// and `web/src/smt-client.ts` for the browser path. Field names use
/// snake_case; the wasm entry point deserializes JS objects with matching
/// snake_case keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtCircuitInputs {
    pub smt_root: String,
    pub serial_number: String,
    pub smt_siblings: Vec<String>,
    pub smt_old_key: String,
    pub smt_old_value: String,
    pub smt_is_old0: String,
}
