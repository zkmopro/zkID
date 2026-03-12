pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "utils/utils.circom";

/// @title Bits2Limbs
/// @notice Convert a bit array to k limbs of n bits each (little-endian limb order)
/// @param totalBits Total number of input bits
/// @param n Number of bits per limb
/// @param k Number of limbs
/// @input in The input bit array
/// @output out Array of k limbs
template Bits2Limbs(totalBits, n, k) {
    signal input in[totalBits];
    signal output out[k];

    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitIdx = i * n + j;
            if (bitIdx < totalBits) {
                b2n[i].in[j] <== in[bitIdx];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

/// @title CertRSA256Verify
/// @notice Verifies an X.509 certificate RSA-SHA256 signature
/// @param maxMessageLength Maximum TBS certificate bytes
/// @param n RSA chunk bits (121)
/// @param k RSA chunks (17 for 2048-bit)
template CertRSA256Verify(maxMessageLength, n, k) {
    // === Inputs ===
    signal input message[maxMessageLength];    // TBS certificate bytes
    signal input messageLength;                // actual TBS length
    signal input rsaModulus[k];                // issuer's RSA public key
    signal input rsaSignature[k];              // certificate signature

    // === Step 1: Assert zero padding ===
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // === Step 2: SHA-256 of TBS certificate ===
    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // === Step 3: Convert SHA-256 to RSA limbs ===
    signal shaReversed[256];
    for (var i = 0; i < 256; i++) {
        shaReversed[i] <== sha[255 - i];
    }

    component hashToLimbs = Bits2Limbs(256, n, k);
    hashToLimbs.in <== shaReversed;

    // === Step 4: RSA Verify ===
    component rsaVerifier = RSAVerifier65537(n, k);
    rsaVerifier.modulus <== rsaModulus;
    rsaVerifier.signature <== rsaSignature;
    rsaVerifier.message <== hashToLimbs.out;
}

/// @title FullCertRSA256Verify
/// @notice Verifies an X.509 certificate RSA-SHA256 signature
/// @param maxMessageLength Maximum TBS certificate bytes
/// @param n RSA chunk bits (121)
/// @param k RSA chunks (17 for 2048-bit)
/// @param modulusBits   Actual RSA key size in bits (e.g. 2048) — must be
///                      divisible by 8. Separate from n*k (e.g. 121*17=2057).
template FullCertRSA256Verify(maxMessageLength, n, k, modulusBits) {
    // === Inputs ===
    signal input tbs[maxMessageLength];    // TBS certificate bytes
    signal input tbs_length;                // actual TBS length
    signal input user_cert[maxMessageLength];    // user certificate bytes
    signal input user_cert_length;                // actual user certificate length
    signal input user_cert_tbs[maxMessageLength]; // user certificate TBS bytes
    signal input user_cert_tbs_offset;        // hint: where TBS starts in user_cert
    signal input user_cert_tbs_length;        // hint: TBS byte length
    signal input user_rsa_modulus[k]; // user's RSA public key
    signal input user_rsa_signature[k];                // certificate signature
    // These are the "parse SPKI" hints the prover supplies:
    signal input user_modulus_offset;      // where modulus bytes start
    signal input user_modulus_tag_offset;  // where 0x02 INTEGER tag is

    signal input issuer_rsa_modulus[k];                  // issuer's RSA public key
    signal input issuer_rsa_signature[k];                // certificate signature

    signal user_rsa_extracted_modulus[k];
    ExtractModulus(maxMessageLength, n, k, modulusBits)(
        in               <== user_cert,
        modulusOffset    <== user_modulus_offset,
        modulusTagOffset <== user_modulus_tag_offset
    ) ==> user_rsa_extracted_modulus;

    // ── Step 1: Extract TBS from user_cert ────────────────────────────────
    // TBS bytes are a sub-array of user_cert
    // Proves user_cert_tbs came from the same cert as the modulus
    signal user_cert_tbs_output[maxMessageLength];
    component tbs_extract[maxMessageLength];
    component tbs_lt[maxMessageLength];
    component tbs_ltn[maxMessageLength];
    signal tbs_inbounds[maxMessageLength];


    for (var i = 0; i < maxMessageLength; i++) {
        // Check i < tbs_length
        tbs_lt[i] = LessThan(12);
        tbs_lt[i].in[0] <== i;
        tbs_lt[i].in[1] <== user_cert_tbs_length;

        // Check tbs_offset + i < maxMessageLength
        tbs_ltn[i] = LessThan(12);
        tbs_ltn[i].in[0] <== user_cert_tbs_offset + i;
        tbs_ltn[i].in[1] <== maxMessageLength;

        // Select byte from user_cert at offset+i, clamp if out of bounds
        tbs_extract[i] = Multiplexer(1, maxMessageLength);
        for (var j = 0; j < maxMessageLength; j++) {
            tbs_extract[i].inp[j][0] <== user_cert[j];
        }
        tbs_extract[i].sel <== tbs_ltn[i].out * (user_cert_tbs_offset + i)
                             + (1 - tbs_ltn[i].out) * 0;

        // Zero out if beyond TBS length or out of bounds
        tbs_inbounds[i] <== tbs_lt[i].out * tbs_ltn[i].out;
        user_cert_tbs_output[i] <== tbs_extract[i].out[0] * tbs_inbounds[i];
    }

    // Validate TBS starts with SEQUENCE tag (0x30)
    component tbsTagSel = Multiplexer(1, maxMessageLength);
    for (var i = 0; i < maxMessageLength; i++) {
        tbsTagSel.inp[i][0] <== user_cert[i];
    }
    tbsTagSel.sel    <== user_cert_tbs_offset;
    tbsTagSel.out[0] === 48;  // 0x30 SEQUENCE tag

    // ── Hash user_cert_tbs and verify issuer signature ────────────────────
    signal user_cert_tbs_hash[k];
    HashAndLimbs(maxMessageLength, n, k)(
        in     <== user_cert_tbs,             
        length <== user_cert_length      
    ) ==> user_cert_tbs_hash;

    // signal user_cert_tbs_hash_output[k];
    // HashAndLimbs(maxMessageLength, n, k)(
    //     in     <== user_cert_tbs_output,             
    //     length <== user_cert_tbs_length      
    // ) ==> user_cert_tbs_hash_output;

    RSAVerifier65537(n, k)(
        modulus   <== issuer_rsa_modulus,
        signature <== issuer_rsa_signature,
        message   <== user_cert_tbs_hash
    );

    // ── Hash tbs and verify user signature ───────────────────────────────
    signal tbs_hash[k];
    HashAndLimbs(maxMessageLength, n, k)(
        in     <== tbs,                         
        length <== tbs_length                    
    ) ==> tbs_hash;

    RSAVerifier65537(n, k)(
        modulus   <== user_rsa_modulus,
        signature <== user_rsa_signature,
        message   <== tbs_hash
    );


    // CertRSA256Verify(maxMessageLength, n, k)(
    //     tbs, 
    //     tbs_length, 
    //     user_rsa_modulus, 
    //     user_rsa_signature
    // );

    // CertRSA256Verify(maxMessageLength, n, k)(
    //     user_cert_tbs, 
    //     user_cert_tbs_length, 
    //     issuer_rsa_modulus, 
    //     issuer_rsa_signature
    // );
}