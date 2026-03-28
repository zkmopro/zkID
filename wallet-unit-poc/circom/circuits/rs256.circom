pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "components/smt-nonmembership.circom";
include "components/serial-extractor.circom";
include "components/dn-extractor.circom";
include "components/poseidon_p256.circom";
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

    // === Output: SHA-256 hash bits (for external use, e.g. TBS binding) ===
    signal output shaOut[256];

    // === Step 1: Assert zero padding ===
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // === Step 2: SHA-256 of TBS certificate ===
    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);
    for (var i = 0; i < 256; i++) {
        shaOut[i] <== sha[i];
    }

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
template FullCertRSA256VerifyWithRevocation(maxMessageLength, n, k, modulusBits, smtDepth) {
    // === Inputs ===
    signal input tbs[maxMessageLength];    // TBS certificate bytes
    signal input tbs_length;                // actual TBS length
    signal input issuer_tbs[maxMessageLength];    // issuer TBS certificate bytes
    signal input issuer_tbs_length;                // issuer TBS length
    signal input actual_issuer_tbs_length; // actual issuer TBS length
    signal input user_cert_zero_padded[maxMessageLength];    // user cert certificate bytes zero padded
    signal input actual_user_cert_length;         // actual user certificate length
    signal input user_rsa_signature[k];                // certificate signature
     // These are the "parse SPKI" hints the prover supplies:
    signal input user_modulus_offset;      // where modulus bytes start
    signal input user_modulus_tag_offset;  // where 0x02 INTEGER tag is

    signal input issuer_rsa_modulus[k];                  // issuer's RSA public key
    signal input issuer_rsa_signature[k];                // certificate signature

    // === SMT Non-Membership Inputs ===
    signal input smtRoot;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Serial Number Extraction Inputs ===
    signal input serial_offset;
    signal input serial_length;

    // === Subject DN Extraction Inputs ===
    signal input subject_dn_offset;
    signal input subject_dn_length;

    // === Outputs ===
    signal output tbs_hash[256];
    signal output dn_nullifier;

    VerifyTBSinCert(maxMessageLength, maxMessageLength)(user_cert_zero_padded, issuer_tbs, actual_issuer_tbs_length);

    signal user_rsa_extracted_modulus[k];
    ExtractModulus(maxMessageLength, n, k, modulusBits)(
        in               <== user_cert_zero_padded,
        modulusOffset    <== user_modulus_offset,
        modulusTagOffset <== user_modulus_tag_offset
    ) ==> user_rsa_extracted_modulus;

    // === User cert RSA verification (captures TBS hash) ===
    signal userShaOut[256];
    CertRSA256Verify(maxMessageLength, n, k)(
        tbs,
        tbs_length,
        user_rsa_extracted_modulus,
        user_rsa_signature
    ) ==> (userShaOut);

    for (var i = 0; i < 256; i++) {
        tbs_hash[i] <== userShaOut[i];
    }

    signal issuerShaOut[256];
    CertRSA256Verify(maxMessageLength, n, k)(
        issuer_tbs,
        issuer_tbs_length,
        issuer_rsa_modulus,
        issuer_rsa_signature
    ) ==> (issuerShaOut);

    // === Serial Number Extraction (replaces external serialNumber input) ===
    var maxSerialLen = 20;  // DER INTEGERs may have a leading 0x00 sign byte; 20 covers up to 19-byte serials
    signal extractedSerial;
    DERSerialExtractor(maxMessageLength, maxSerialLen)(
        in           <== user_cert_zero_padded,
        serialOffset <== serial_offset,
        serialLength <== serial_length
    ) ==> (extractedSerial);

    SMTNonMembershipVerifier(smtDepth)(
        smtRoot,
        extractedSerial,
        smtSiblings,
        smtOldKey,
        smtOldValue,
        smtIsOld0
    );

    // === Subject DN Extraction ===
    var maxDNLen = 256;
    signal extractedDN[maxDNLen];
    signal extractedDNLen;
    ExtractSubjectDN(maxMessageLength, maxDNLen)(
        in       <== user_cert_zero_padded,
        dnOffset <== subject_dn_offset,
        dnLength <== subject_dn_length
    ) ==> (extractedDN, extractedDNLen);

    // === Nullifier: Pack DN bytes into 9 chunks and Poseidon chain ===
    // Pack 256 bytes into 9 field elements (31 bytes each, big-endian)
    var nChunks = 9;  // ceil(256 / 31) = 9 (last chunk: 256 - 8*31 = 8 bytes)

    signal chunks[nChunks];
    signal chunkAcc[nChunks][32];  // [chunk_index][accumulator_step]
    for (var c = 0; c < nChunks; c++) {
        chunkAcc[c][0] <== 0;
        for (var j = 0; j < 31; j++) {
            var byteIdx = c * 31 + j;
            if (byteIdx < maxDNLen) {
                chunkAcc[c][j + 1] <== chunkAcc[c][j] * 256 + extractedDN[byteIdx];
            } else {
                chunkAcc[c][j + 1] <== chunkAcc[c][j] * 256;  // pad with zero
            }
        }
        chunks[c] <== chunkAcc[c][31];
    }

    // Sequential Poseidon chain: h = Poseidon(chunk[0], chunk[1]),
    //   then h = Poseidon(h, chunk[i]) for i=2..8
    component posHash[nChunks - 1];  // 8 Poseidon calls
    signal hashChain[nChunks - 1];

    posHash[0] = PoseidonP256(2);
    posHash[0].inputs[0] <== chunks[0];
    posHash[0].inputs[1] <== chunks[1];
    hashChain[0] <== posHash[0].out;

    for (var i = 1; i < nChunks - 1; i++) {
        posHash[i] = PoseidonP256(2);
        posHash[i].inputs[0] <== hashChain[i - 1];
        posHash[i].inputs[1] <== chunks[i + 1];
        hashChain[i] <== posHash[i].out;
    }

    dn_nullifier <== hashChain[nChunks - 2];
}