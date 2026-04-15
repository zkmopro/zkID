//! Asserts the bundled fixture's signature is a valid PKCS#1 v1.5 signature
//! over `SHA-256(DEFAULT_TBS)`. Fails if the fixture and `main.rs:139` drift.

// Mirror of main.rs:139 — keep in sync.
const DEFAULT_TBS: &[u8] = b"e775f2805fb993e05a208dbff15d1c1";

#[test]
fn fixture_signature_matches_default_tbs() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
        RsaPublicKey,
    };
    use sha2::Sha256;
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    let response_str = std::fs::read_to_string("tests/testdata/response_sign_test.json")
        .expect("response_sign_test.json not found — run `cargo run --example generate_fixtures` first");
    let response: serde_json::Value = serde_json::from_str(&response_str)
        .expect("invalid JSON in response_sign_test.json");

    let cert_der = B64
        .decode(response["certb64"].as_str().expect("missing certb64 field"))
        .expect("certb64 base64 decode failed");
    let sig_bytes = B64
        .decode(response["signature"].as_str().expect("missing signature field"))
        .expect("signature base64 decode failed");

    let cert = Certificate::from_der(&cert_der).expect("cert DER parse failed");
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI encode failed");
    let pub_key =
        RsaPublicKey::from_public_key_der(&spki_der).expect("RSA pub key decode failed");

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let signature =
        Signature::try_from(sig_bytes.as_slice()).expect("signature format invalid");

    verifying_key.verify(DEFAULT_TBS, &signature).expect(
        "Fixture signature does not match SHA-256(DEFAULT_TBS). \
         Regenerate with: cargo run --example generate_fixtures",
    );
}
