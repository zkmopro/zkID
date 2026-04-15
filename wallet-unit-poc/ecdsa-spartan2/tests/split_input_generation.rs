//! Tests for `generate_split_inputs` — verifies the split input JSONs have
//! correct structure and that pk_blind is shared between cert-chain and
//! device-sig outputs.

use ecdsa_spartan2::{
    generate_split_inputs,
    circuits::sha256rsa_circuit::{CardSignResponse, Pkcs11InfoResponse},
    CertChainCircuit, DEFAULT_TBS,
};

fn load_rs2048_fixtures() -> (x509_cert::Certificate, String, x509_cert::Certificate, String) {
    let response_str = std::fs::read_to_string("tests/testdata/response_sign_test.json")
        .expect("response_sign_test.json not found — run `cargo run --example generate_fixtures`");
    let response: CardSignResponse =
        serde_json::from_str(&response_str).expect("invalid JSON in response_sign_test.json");

    let pkcs11_str = std::fs::read_to_string("tests/testdata/pkcs11info_test.json")
        .expect("pkcs11info_test.json not found — run `cargo run --example generate_fixtures`");
    let pkcs11: Pkcs11InfoResponse =
        serde_json::from_str(&pkcs11_str).expect("invalid JSON in pkcs11info_test.json");

    let issuer_cert =
        CertChainCircuit::extract_issuer_cert(&pkcs11).expect("failed to extract issuer cert");
    let user_cert = CertChainCircuit::generate_user_cert_from_certb64(&response.certb64)
        .expect("failed to parse user cert");

    let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
    let serial_hex = hex::encode(serial_bytes);

    (user_cert, response.signature, issuer_cert, serial_hex)
}

#[test]
fn split_inputs_have_expected_structure() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs2048_fixtures();

    let (cert_chain, device_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        17,
        17,
    )
    .expect("generate_split_inputs failed");

    // cert_chain JSON must have all expected keys
    for key in [
        "user_cert_zero_padded",
        "actual_user_cert_length",
        "user_modulus_offset",
        "user_modulus_tag_offset",
        "subject_dn",
        "subject_dn_offset",
        "subject_dn_length",
        "serial_number_offset",
        "issuer_tbs",
        "issuer_tbs_length",
        "actual_issuer_tbs_length",
        "issuer_rsa_modulus",
        "issuer_rsa_signature",
        "smtRoot",
        "serialNumber",
        "smtSiblings",
        "smtOldKey",
        "smtOldValue",
        "smtIsOld0",
        "pk_blind",
    ] {
        assert!(
            cert_chain.get(key).is_some(),
            "cert_chain missing key: {key}"
        );
    }

    // device_sig JSON must have all expected keys
    for key in ["tbs", "tbs_length", "user_pk_limbs", "user_rsa_signature", "pk_blind"] {
        assert!(
            device_sig.get(key).is_some(),
            "device_sig missing key: {key}"
        );
    }

    // Array dimensions
    assert_eq!(
        cert_chain["user_cert_zero_padded"].as_array().unwrap().len(),
        1536,
        "user_cert_zero_padded length"
    );
    assert_eq!(
        cert_chain["issuer_rsa_modulus"].as_array().unwrap().len(),
        17,
        "issuer_rsa_modulus length (k_issuer=17)"
    );
    assert_eq!(
        cert_chain["smtSiblings"].as_array().unwrap().len(),
        128,
        "smtSiblings length (smtDepth=128)"
    );
    assert_eq!(
        device_sig["tbs"].as_array().unwrap().len(),
        1536,
        "tbs length (maxMessageLength=1536)"
    );
    assert_eq!(
        device_sig["user_pk_limbs"].as_array().unwrap().len(),
        17,
        "user_pk_limbs length (k_user=17)"
    );
    assert_eq!(
        device_sig["user_rsa_signature"].as_array().unwrap().len(),
        17,
        "user_rsa_signature length (k_user=17)"
    );
}

#[test]
fn split_inputs_share_pk_blind() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs2048_fixtures();

    let (cert_chain, device_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        17,
        17,
    )
    .expect("generate_split_inputs failed");

    let cc_blind = cert_chain["pk_blind"].as_str().expect("cert_chain pk_blind not a string");
    let ds_blind = device_sig["pk_blind"].as_str().expect("device_sig pk_blind not a string");
    assert_eq!(
        cc_blind, ds_blind,
        "pk_blind must be identical across cert-chain and device-sig outputs"
    );
}
