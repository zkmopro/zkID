pragma circom 2.2.3;

include "rs256.circom";
include "components/pk_commit.circom";

/// @title CertChainRSA256
/// @notice Circuit A of the CertChain + DeviceSig pair. Proves: "I hold a
///         non-revoked, MOICA-issued cert whose RSA public key hashes (with
///         pk_blind) to pk_commit." Issuer RSA params are separate from user
///         params so MOICA-G3's 4096-bit CA can certify a 2048-bit user key.
///         pk_commit is computed over k_user limbs so it byte-matches
///         DeviceSigRSA256's; the verifier checks `pk_commit_A == pk_commit_B`
///         to prevent proof-mixing.
///
/// @param maxMessageLength    Max TBS / cert byte length (1536)
/// @param n                   RSA limb bits (e.g. 121)
/// @param k_issuer            Issuer RSA limb count (17 for G2, 34 for G3)
/// @param modulusBitsIssuer   Issuer RSA key bits (2048 for G2, 4096 for G3)
/// @param k_user              User RSA limb count (always 17 — MOICA user keys are 2048-bit)
/// @param modulusBitsUser     User RSA key bits (always 2048)
/// @param smtDepth            SMT non-membership proof depth (e.g. 128)
/// @param maxSerialNumberLength  Max cert serial bytes (e.g. 16)
template CertChainRSA256(
    maxMessageLength,
    n,
    k_issuer,
    modulusBitsIssuer,
    k_user,
    modulusBitsUser,
    smtDepth,
    maxSerialNumberLength
) {
    // === User cert (outer DER wrapper — TBS starts at byte 4) ===
    signal input user_cert_zero_padded[maxMessageLength];
    signal input actual_user_cert_length;

    // All offsets are relative to issuer_tbs[0] (i.e. user_cert[4]).
    // The circuit enforces each offset lies within [0, actual_issuer_tbs_length)
    // before use, so the prover cannot point outside the MOICA-signed region.
    signal input tbs_modulus_offset;
    signal input tbs_modulus_tag_offset;

    // === Serial extraction ===
    // Points to first serial byte in issuer_tbs; tag is at offset-2, length at offset-1.
    signal input tbs_serial_number_offset;

    // === Issuer (cert chain) — sized to k_issuer ===
    signal input issuer_tbs[maxMessageLength];
    signal input issuer_tbs_length;
    signal input actual_issuer_tbs_length;
    signal input issuer_rsa_modulus[k_issuer];
    signal input issuer_rsa_signature[k_issuer];

    // === Revocation (SMT non-membership) ===
    signal input smtRoot;
    signal input serialNumber;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Linking (private; same value used in DeviceSigRSA256) ===
    signal input pk_blind;

    // === Outputs ===
    signal output pk_commit;

    // ── Step 1: Prove user cert embeds the MOICA-signed TBS ───────────────
    // After this, issuer_tbs[0..actual_issuer_tbs_length) is identical to
    // user_cert_zero_padded[4..4+actual_issuer_tbs_length).
    VerifyTBSinCert(maxMessageLength, maxMessageLength)(
        user_cert_zero_padded,
        issuer_tbs,
        actual_issuer_tbs_length
    );

    // Enforce zero-padding on user_cert_zero_padded beyond its actual length,
    // preventing a prover from stuffing arbitrary bytes in the padding region.
    AssertZeroPadding(maxMessageLength)(user_cert_zero_padded, actual_user_cert_length);

    // ── Step 2: Bound actual_issuer_tbs_length to 13 bits ─────────────────
    // AssertSliceInTBS requires this; see its doc in utils/utils.circom.
    component tlRange = Num2Bits(13);
    tlRange.in <== actual_issuer_tbs_length;

    var modulusBytes = modulusBitsUser \ 8;  // e.g. 2048/8 = 256

    // ── Steps 3–6: Enforce every offset lies inside the signed TBS ────────

    component moTagBnd = AssertSliceInTBS();
    moTagBnd.offset <== tbs_modulus_tag_offset;
    moTagBnd.length <== 1;
    moTagBnd.tbsLen <== actual_issuer_tbs_length;

    component moBnd = AssertSliceInTBS();
    moBnd.offset <== tbs_modulus_offset;
    moBnd.length <== modulusBytes;
    moBnd.tbsLen <== actual_issuer_tbs_length;

    // Serial: VerifySerialNumber reads tag at (offset-2) and len at (offset-1),
    // so offset must be >= 2 in addition to the upper-bound check.
    component snLow = GreaterEqThan(13);
    snLow.in[0] <== tbs_serial_number_offset;
    snLow.in[1] <== 2;
    snLow.out === 1;

    component snBnd = AssertSliceInTBS();
    snBnd.offset <== tbs_serial_number_offset;
    snBnd.length <== maxSerialNumberLength;
    snBnd.tbsLen <== actual_issuer_tbs_length;

    // ── Step 7: Extract and verify serial number from issuer_tbs ─────────
    VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
        issuer_tbs,
        tbs_serial_number_offset,
        serialNumber
    );

    // ── Step 8: Extract RSA modulus from issuer_tbs ───────────────────────
    signal user_rsa_extracted_modulus[k_user];
    ExtractModulus(maxMessageLength, n, k_user, modulusBitsUser)(
        in               <== issuer_tbs,
        modulusOffset    <== tbs_modulus_offset,
        modulusTagOffset <== tbs_modulus_tag_offset
    ) ==> user_rsa_extracted_modulus;

    // ── Step 9: Verify issuer RSA-SHA256 signature over issuer_tbs ───────
    CertRSA256Verify(maxMessageLength, n, k_issuer)(
        issuer_tbs,
        issuer_tbs_length,
        issuer_rsa_modulus,
        issuer_rsa_signature
    );

    // ── Step 10: Revocation check (SMT non-membership) ───────────────────
    SMTNonMembershipVerifier(smtDepth)(
        smtRoot,
        serialNumber,
        smtSiblings,
        smtOldKey,
        smtOldValue,
        smtIsOld0
    );

    // ── Step 11: Commit to the user RSA public key ────────────────────────
    // Sized to k_user so pk_commit byte-matches DeviceSigRSA256's output.
    component pkCommit = ChunkedPoseidonP256(k_user + 1);
    for (var i = 0; i < k_user; i++) {
        pkCommit.inputs[i] <== user_rsa_extracted_modulus[i];
    }
    pkCommit.inputs[k_user] <== pk_blind;
    pk_commit <== pkCommit.out;
}
