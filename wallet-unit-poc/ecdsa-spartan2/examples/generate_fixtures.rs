//! Deterministic synthetic test fixture generator.
//!
//! Overwrites:
//!   tests/testdata/response_sign_test.json
//!   tests/testdata/pkcs11info_test.json
//!
//! Both files are byte-for-byte reproducible given the same SEED.
//! The signature in response_sign_test.json is a valid PKCS#1 v1.5
//! SHA-256 signature over the DEFAULT_TBS challenge, matching main.rs:139.
//!
//! Usage:
//!   cargo run --example generate_fixtures

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use der::Encode;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::Keypair as _;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::UtcTime;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

// Canonical challenge value — mirrors main.rs:139. DO NOT change here.
const DEFAULT_TBS: &[u8] = b"e775f2805fb993e05a208dbff15d1c1";

// Determinism seed. Change only to rotate synthetic keys.
const SEED: [u8; 32] = [
    0x7a, 0x6b, 0x49, 0x44, 0x5f, 0x74, 0x65, 0x73,
    0x74, 0x5f, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72,
    0x65, 0x73, 0x5f, 0x73, 0x65, 0x65, 0x64, 0x5f,
    0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Hex-encoded serials — kept stable to minimise git diff when keys rotate.
const CA_SERIAL_HEX: &str = "26c76ee1317398df0a955d312f0645703a47418f";
const USER_SERIAL_HEX: &str = "5e4fad0a7c6dd854be121e7a00733b212c1aed8a";

// Fixed validity window so cert DER is byte-identical across regeneration days.
// 2026-01-01T00:00:00Z → 2036-01-01T00:00:00Z (10 years)
const NOT_BEFORE_UNIX: u64 = 1_735_689_600;
const VALIDITY_SECONDS: u64 = 10 * 365 * 24 * 3600;

type BoxErr = Box<dyn std::error::Error>;

fn main() -> Result<(), BoxErr> {
    let ca_key = generate_rsa_key(0)?;
    let user_key = generate_rsa_key(1)?;

    let ca_cert = generate_ca_cert(&ca_key)?;
    let user_cert = generate_user_cert(&user_key, &ca_key, &ca_cert)?;
    let signature = sign_test_challenge(&user_key)?;

    let ca_der = ca_cert.to_der()?;
    let user_der = user_cert.to_der()?;

    write_response_sign(&user_der, &signature)?;
    write_pkcs11info(&ca_der, &user_der)?;

    println!("Fixtures written to tests/testdata/");
    println!("  response_sign_test.json  — user cert + signature over DEFAULT_TBS");
    println!("  pkcs11info_test.json     — CA cert + user cert");
    Ok(())
}

fn generate_rsa_key(index: u8) -> Result<RsaPrivateKey, BoxErr> {
    let mut seed = SEED;
    seed[31] ^= index;
    let mut rng = ChaCha20Rng::from_seed(seed);
    Ok(RsaPrivateKey::new(&mut rng, 2048)?)
}

fn fixed_validity() -> Result<Validity, BoxErr> {
    let not_before = Time::UtcTime(UtcTime::from_unix_duration(
        Duration::from_secs(NOT_BEFORE_UNIX),
    )?);
    let not_after = Time::UtcTime(UtcTime::from_unix_duration(
        Duration::from_secs(NOT_BEFORE_UNIX + VALIDITY_SECONDS),
    )?);
    Ok(Validity { not_before, not_after })
}

fn generate_ca_cert(ca_key: &RsaPrivateKey) -> Result<x509_cert::Certificate, BoxErr> {
    let serial = SerialNumber::new(&hex::decode(CA_SERIAL_HEX)?)?;
    let subject: Name =
        "C=TW,O=Test Government CA,OU=Test Certificate Authority".parse()?;
    let signer = SigningKey::<Sha256>::new(ca_key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key())?;

    let builder = CertificateBuilder::new(
        Profile::Root,
        serial,
        fixed_validity()?,
        subject,
        spki,
        &signer,
    )?;

    Ok(builder.build::<rsa::pkcs1v15::Signature>()?)
}

fn generate_user_cert(
    user_key: &RsaPrivateKey,
    ca_key: &RsaPrivateKey,
    ca_cert: &x509_cert::Certificate,
) -> Result<x509_cert::Certificate, BoxErr> {
    let serial = SerialNumber::new(&hex::decode(USER_SERIAL_HEX)?)?;
    let subject: Name = "C=TW,CN=Test User,serialNumber=0000000000000000".parse()?;
    let issuer_name = ca_cert.tbs_certificate.subject.clone();

    let ca_signer = SigningKey::<Sha256>::new(ca_key.clone());
    let user_signer = SigningKey::<Sha256>::new(user_key.clone());
    let user_spki = SubjectPublicKeyInfoOwned::from_key(user_signer.verifying_key())?;

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        fixed_validity()?,
        subject,
        user_spki,
        &ca_signer,
    )?;

    Ok(builder.build::<rsa::pkcs1v15::Signature>()?)
}

fn sign_test_challenge(user_key: &RsaPrivateKey) -> Result<Vec<u8>, BoxErr> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let signer = SigningKey::<Sha256>::new(user_key.clone());
    let sig: rsa::pkcs1v15::Signature = signer.try_sign(DEFAULT_TBS)?;
    Ok(sig.to_vec())
}

fn write_response_sign(user_der: &[u8], sig_bytes: &[u8]) -> Result<(), BoxErr> {
    let payload = serde_json::json!({
        "cardSN":     "TEST000000000000",
        "certb64":    B64.encode(user_der),
        "func":       "sign",
        "last_error": 0,
        "ret_code":   0,
        "signature":  B64.encode(sig_bytes),
        "version":    "0.0.0"
    });
    std::fs::write(
        "tests/testdata/response_sign_test.json",
        serde_json::to_string_pretty(&payload)?,
    )?;
    Ok(())
}

fn write_pkcs11info(ca_der: &[u8], user_der: &[u8]) -> Result<(), BoxErr> {
    let payload = serde_json::json!({
        "func":       "pkcs11info",
        "last_error": 0,
        "ret_code":   0,
        "slots": [{
            "token": {
                "certs": [
                    {
                        "certb64":   B64.encode(ca_der),
                        "label":     "CA Cert",
                        "subjectDN": "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "issuerDN":  "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "usage":     "keyCertSign|cRLSign"
                    },
                    {
                        "certb64":   B64.encode(user_der),
                        "label":     "cert1",
                        "subjectDN": "C=TW,CN=Test User,serialNumber=0000000000000000",
                        "issuerDN":  "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "usage":     "digitalSignature"
                    }
                ]
            }
        }]
    });
    std::fs::write(
        "tests/testdata/pkcs11info_test.json",
        serde_json::to_string_pretty(&payload)?,
    )?;
    Ok(())
}
