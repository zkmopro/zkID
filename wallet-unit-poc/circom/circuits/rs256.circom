pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "components/smt-nonmembership.circom";

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

/// @title CertRSA256VerifyWithRevocation
/// @notice Verifies an X.509 certificate RSA-SHA256 signature and proves
///         the certificate's serial number is NOT in the revocation SMT
/// @param maxMessageLength Maximum TBS certificate bytes
/// @param n RSA chunk bits (121)
/// @param k RSA chunks (17 for 2048-bit)
/// @param smtDepth Sparse Merkle Tree depth (128)
template CertRSA256VerifyWithRevocation(maxMessageLength, n, k, smtDepth) {
    // === RSA Verification Inputs ===
    signal input message[maxMessageLength];
    signal input messageLength;
    signal input rsaModulus[k];
    signal input rsaSignature[k];

    // === SMT Non-Membership Inputs ===
    signal input smtRoot;
    signal input serialNumber;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Step 1: RSA-SHA256 Verification (same as CertRSA256Verify) ===
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);

    signal shaReversed[256];
    for (var i = 0; i < 256; i++) {
        shaReversed[i] <== sha[255 - i];
    }

    component hashToLimbs = Bits2Limbs(256, n, k);
    hashToLimbs.in <== shaReversed;

    component rsaVerifier = RSAVerifier65537(n, k);
    rsaVerifier.modulus <== rsaModulus;
    rsaVerifier.signature <== rsaSignature;
    rsaVerifier.message <== hashToLimbs.out;

    // === Step 2: SMT Non-Membership Proof (revocation check) ===
    component smtVerifier = SMTNonMembershipVerifier(smtDepth);
    smtVerifier.root <== smtRoot;
    smtVerifier.key <== serialNumber;
    smtVerifier.siblings <== smtSiblings;
    smtVerifier.oldKey <== smtOldKey;
    smtVerifier.oldValue <== smtOldValue;
    smtVerifier.isOld0 <== smtIsOld0;
}
