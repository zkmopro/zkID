pragma circom 2.2.3;

include "rs256.circom";
include "components/pk_commit.circom";

/// @title DeviceSigRSA256
/// @notice Circuit B of the CertChain + DeviceSig pair. Verifies an RSA
///         signature over `app_id_bytes`, emits `pk_commit` (matched against
///         CertChainRSA256) and `nullifier = ChunkedPoseidonP256(signature)`.
///         Determinism of PKCS#1 v1.5 over a fixed payload makes the nullifier
///         per-(card, app_id) stable; signature stays private to the card, so
///         it cannot be precomputed from public inputs.
///
///         The card signs the SHA-256-padded `tbs`, not the raw 31 bytes;
///         binding `tbs[0..31] === app_id_bytes` is sufficient because any
///         tamper to the padding region changes the digest and breaks RSA verify.
///
/// @param maxMessageLength  Max byte length of `tbs` (1536)
/// @param n                 RSA limb bits (e.g. 121)
/// @param k                 RSA limb count (17 for 2048-bit, 34 for 4096-bit)
template DeviceSigRSA256(maxMessageLength, n, k) {
    signal input app_id_bytes[31];

    // SHA-256-padded form of app_id_bytes; produced by the input builder.
    signal input tbs[maxMessageLength];
    signal input tbs_length;

    signal input user_pk_limbs[k];
    signal input user_rsa_signature[k];

    // Must match CertChainRSA256's pk_blind.
    signal input pk_blind;

    signal output pk_commit;
    signal output nullifier;

    for (var i = 0; i < 31; i++) {
        tbs[i] === app_id_bytes[i];
    }

    CertRSA256Verify(maxMessageLength, n, k)(
        tbs,
        tbs_length,
        user_pk_limbs,
        user_rsa_signature
    );

    component pkCommit = ChunkedPoseidonP256(k + 1);
    for (var i = 0; i < k; i++) {
        pkCommit.inputs[i] <== user_pk_limbs[i];
    }
    pkCommit.inputs[k] <== pk_blind;
    pk_commit <== pkCommit.out;

    component nullifierHash = ChunkedPoseidonP256(k);
    for (var i = 0; i < k; i++) {
        nullifierHash.inputs[i] <== user_rsa_signature[i];
    }
    nullifier <== nullifierHash.out;
}
