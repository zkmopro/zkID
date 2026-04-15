//! Integration test: verifies the bundled test fixture is internally consistent.
//!
//! Raw-decrypts the signature from response_sign_test.json (sig^e mod n),
//! extracts the trailing 32 bytes of the PKCS#1 v1.5 DigestInfo envelope,
//! and asserts they equal SHA-256(DEFAULT_TBS).
//!
//! DEFAULT_TBS is a local copy of the canonical value in src/main.rs:139.
//! If that value changes, update this constant AND regenerate the fixtures
//! via `cargo run --example generate_fixtures`.

const DEFAULT_TBS: &[u8] = b"e775f2805fb993e05a208dbff15d1c1";
const E: u64 = 65537;

#[test]
fn fixture_signature_matches_default_tbs() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use num_bigint::BigUint;
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use x509_cert::{der::Decode, der::Encode, Certificate};

    let response_str = std::fs::read_to_string("tests/testdata/response_sign_test.json")
        .expect("response_sign_test.json not found — run `cargo run --example generate_fixtures` first");

    let response: serde_json::Value =
        serde_json::from_str(&response_str).expect("invalid JSON in response_sign_test.json");

    let cert_b64 = response["certb64"].as_str().expect("missing certb64");
    let sig_b64 = response["signature"].as_str().expect("missing signature");

    let cert_der = B64.decode(cert_b64).expect("certb64 base64 decode failed");
    let sig_bytes = B64.decode(sig_b64).expect("signature base64 decode failed");

    let cert = Certificate::from_der(&cert_der).expect("cert DER parse failed");
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI encode failed");
    let pub_key =
        RsaPublicKey::from_public_key_der(&spki_der).expect("RSA pub key decode failed");

    // rsa crate uses num-bigint-dig internally; convert modulus to num-bigint via bytes
    let n_bytes = pub_key.n().to_bytes_be();
    let n = BigUint::from_bytes_be(&n_bytes);
    let e_big = BigUint::from(E);
    let sig_int = BigUint::from_bytes_be(&sig_bytes);
    let decrypted = sig_int.modpow(&e_big, &n);

    let modulus_len = (n.bits() as usize + 7) / 8;
    let mut decrypted_bytes = vec![0u8; modulus_len];
    let raw = decrypted.to_bytes_be();
    let offset = modulus_len - raw.len();
    decrypted_bytes[offset..].copy_from_slice(&raw);

    assert_eq!(decrypted_bytes[0], 0x00, "PKCS#1 v1.5: first byte must be 0x00");
    assert_eq!(decrypted_bytes[1], 0x01, "PKCS#1 v1.5: second byte must be 0x01 (type 1)");

    let recovered_hash = &decrypted_bytes[modulus_len - 32..];
    let expected_hash: [u8; 32] = Sha256::digest(DEFAULT_TBS).into();

    assert_eq!(
        recovered_hash, &expected_hash,
        "Fixture signature does not match SHA-256(DEFAULT_TBS). \
         Regenerate with: cargo run --example generate_fixtures"
    );
}
