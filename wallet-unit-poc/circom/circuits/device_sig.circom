pragma circom 2.2.3;

include "rs256.circom";
include "components/pk_commit.circom";

/// @title DeviceSigRSA256
/// @notice Phase 2 split — Circuit B of the CertChain + DeviceSig pair.
///         Proves: "I just signed `tbs` with the RSA private key whose public
///         key (combined with pk_blind) hashes to pk_commit."
///
///         Replaces the user-device-signature half of the legacy
///         FullCertRSA256VerifyWithRevocation. Pairs with CertChainRSA256 in
///         cert_chain.circom; the verifier checks pk_commit_A == pk_commit_B
///         to bind the two proofs to the same user.
///
///         `tbs` is the arbitrary byte string the HiPKI card signs via its
///         /sign endpoint — semantically a server challenge. The circuit
///         outputs a PackBytes commitment to it (`packed_tbs`) so the verifier
///         can confirm what was signed.
///
/// @param maxMessageLength  Max byte length of `tbs` (e.g. 1536; Phase 3 will
///                          tighten this to ~256 once HiPKI payload bound is
///                          confirmed)
/// @param n                 RSA limb bits (e.g. 121)
/// @param k                 RSA limb count (17 for 2048-bit, 34 for 4096-bit)
template DeviceSigRSA256(maxMessageLength, n, k) {
    // === User-signed payload ===
    signal input tbs[maxMessageLength];
    signal input tbs_length;

    // === User's RSA public key + signature (private) ===
    signal input user_pk_limbs[k];
    signal input user_rsa_signature[k];

    // === Linking (private; must match CertChainRSA256's pk_blind) ===
    signal input pk_blind;

    // === Outputs ===
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (maxMessageLength + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal output pk_commit;
    signal output packed_tbs;

    // --- Step 1: device-signature verify (user_pk verifies sig over tbs) ---
    CertRSA256Verify(maxMessageLength, n, k)(
        tbs,
        tbs_length,
        user_pk_limbs,
        user_rsa_signature
    );

    // --- Step 2: pk_commit = ChunkedPoseidonP256(user_pk_limbs ‖ pk_blind) ---
    //     Same construction as CertChainRSA256 — verifier asserts equality.
    component pkCommit = ChunkedPoseidonP256(k + 1);
    for (var i = 0; i < k; i++) {
        pkCommit.inputs[i] <== user_pk_limbs[i];
    }
    pkCommit.inputs[k] <== pk_blind;
    pk_commit <== pkCommit.out;

    // --- Step 3: packed_tbs commits to what was signed (public output) ---
    var MAX_TBS_BYTES = 31;
    signal packed_tbs_fields[1];
    PackBytes(MAX_TBS_BYTES, maxMessageLength)(tbs) ==> packed_tbs_fields;
    packed_tbs <== packed_tbs_fields[0];
}
