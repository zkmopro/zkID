pragma circom 2.2.3;

include "rs256.circom";
include "components/pkCommit.circom";

/// @title CertChainRSA256
/// @notice Circuit A of the CertChain + UserSig pair. Proves: "I hold a
///         non-revoked, MOICA-issued cert whose RSA public key hashes (with
///         pkBlind) to pkCommit." Issuer RSA params are separate from user
///         params so MOICA-G3's 4096-bit CA can certify a 2048-bit user key.
///         pkCommit is computed over kUser limbs so it byte-matches
///         UserSigRSA256's; the verifier checks `pk_commit_A == pk_commit_B`
///         to prevent proof-mixing.
///
/// @param maxMessageLength    Max TBS / cert byte length (1536)
/// @param n                   RSA limb bits (e.g. 121)
/// @param kIssuer            Issuer RSA limb count (17 for G2, 34 for G3)
/// @param modulusBitsIssuer   Issuer RSA key bits (2048 for G2, 4096 for G3)
/// @param kUser              User RSA limb count (always 17 — MOICA user keys are 2048-bit)
/// @param modulusBitsUser     User RSA key bits (always 2048)
/// @param smtDepth            SMT non-membership proof depth (e.g. 128)
/// @param maxSerialNumberLength  Max cert serial bytes (e.g. 16)
template CertChainRSA256(
    maxMessageLength,
    n,
    kIssuer,
    modulusBitsIssuer,
    kUser,
    modulusBitsUser,
    smtDepth,
    maxSerialNumberLength
) {
    // === User cert (outer DER wrapper — TBS starts at byte 4) ===
    signal input userCertZeroPadded[maxMessageLength];
    signal input actualUserCertLength;

    // All offsets are relative to issuerTbs[0] (i.e. user_cert[4]).
    // The circuit enforces each offset lies within [0, actualIssuerTbsLength)
    // before use, so the prover cannot point outside the MOICA-signed region.
    signal input tbsModulusOffset;
    signal input tbsModulusTagOffset;

    // === Issuer (cert chain) — sized to kIssuer ===
    signal input issuerTbs[maxMessageLength];
    signal input issuerTbsLength;
    signal input actualIssuerTbsLength;
    signal input issuerRsaModulus[kIssuer];
    signal input issuerRsaSignature[kIssuer];

    // === Revocation (SMT non-membership) ===
    signal input smtRoot;
    signal input serialNumber;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Linking (private; same value used in UserSigRSA256) ===
    signal input pkBlind;

    // === Outputs ===
    signal output pkCommit;

    // ── Step 1: Prove user cert embeds the MOICA-signed TBS ───────────────
    // After this, issuerTbs[0..actualIssuerTbsLength) is identical to
    // userCertZeroPadded[4..4+actualIssuerTbsLength).
    VerifyTBSinCert(maxMessageLength, maxMessageLength)(
        userCertZeroPadded,
        issuerTbs,
        actualIssuerTbsLength
    );

    // Enforce zero-padding on userCertZeroPadded beyond its actual length,
    // preventing a prover from stuffing arbitrary bytes in the padding region.
    AssertZeroPadding(maxMessageLength)(userCertZeroPadded, actualUserCertLength);

    // ── Step 2: Bound actualIssuerTbsLength to 13 bits ─────────────────
    // AssertSliceInTBS requires this; see its doc in utils/utils.circom.
    component tlRange = Num2Bits(13);
    tlRange.in <== actualIssuerTbsLength;

    // ── Step 2b: Bind issuerTbsLength to actualIssuerTbsLength ──────────
    // issuerTbsLength is the SHA-256-padded length; actualIssuerTbsLength
    // is the raw DER length. Without bounding their difference, the prover
    // could set issuerTbsLength >> actualIssuerTbsLength and hide arbitrary
    // bytes in issuerTbs[actual..padded) — bytes the MOICA signature covers
    // but VerifyTBSinCert does not bind to userCertZeroPadded.
    // SHA-256 padding adds between 9 and 72 bytes; use 128 as a safe
    // power-of-two upper bound: actual <= padded <= actual + 128.
    component tbsLenLB = LessEqThan(13);
    tbsLenLB.in[0] <== actualIssuerTbsLength;
    tbsLenLB.in[1] <== issuerTbsLength;
    tbsLenLB.out === 1;

    component tbsLenUB = LessEqThan(14);
    tbsLenUB.in[0] <== issuerTbsLength;
    tbsLenUB.in[1] <== actualIssuerTbsLength + 128;
    tbsLenUB.out === 1;

    var modulusBytes = modulusBitsUser \ 8;  // e.g. 2048/8 = 256

    // ── Steps 3–6: Enforce every offset lies inside the signed TBS ────────

    AssertSliceInTBS()(tbsModulusTagOffset, 1, actualIssuerTbsLength);
    AssertSliceInTBS()(tbsModulusOffset, modulusBytes, actualIssuerTbsLength);

    // ── Step 7a: Walk DER and derive the canonical serial-INTEGER offset ──
    //
    // MOICA TBSes are always > 256 bytes, so the outer SEQUENCE header is
    // always the 4-byte form [0x30, 0x82, len_hi, len_lo]. The two length
    // bytes are not constrained — they vary per cert.
    issuerTbs[0] === 0x30;
    issuerTbs[1] === 0x82;

    // Optional [0] EXPLICIT version block at offset 4.
    // hasVersion=1 ⇒ canonical 5-byte block [0xa0, 0x03, 0x02, 0x01, 0x02]; serial tag at 9.
    // hasVersion=0 ⇒ serial INTEGER tag at offset 4 (v1/v2).
    component hasVersion = IsEqual();
    hasVersion.in[0] <== issuerTbs[4];
    hasVersion.in[1] <== 0xa0;

    component vLen = ForceEqualIfEnabled();
    vLen.enabled <== hasVersion.out;
    vLen.in[0] <== issuerTbs[5];
    vLen.in[1] <== 0x03;

    component vIntTag = ForceEqualIfEnabled();
    vIntTag.enabled <== hasVersion.out;
    vIntTag.in[0] <== issuerTbs[6];
    vIntTag.in[1] <== 0x02;

    component vIntLen = ForceEqualIfEnabled();
    vIntLen.enabled <== hasVersion.out;
    vIntLen.in[0] <== issuerTbs[7];
    vIntLen.in[1] <== 0x01;

    component vIntVal = ForceEqualIfEnabled();
    vIntVal.enabled <== hasVersion.out;
    vIntVal.in[0] <== issuerTbs[8];
    vIntVal.in[1] <== 0x02;

    signal serialTagOff <== 4 + hasVersion.out * 5;
    signal serialValueOff <== serialTagOff + 2;

    // ── Step 7b: Extract and verify serial number from issuerTbs ─────────
    VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
        issuerTbs,
        serialValueOff,
        serialNumber
    );

    // ── Step 8: Extract RSA modulus from issuerTbs ───────────────────────
    signal userRsaExtractedModulus[kUser];
    ExtractModulus(maxMessageLength, n, kUser, modulusBitsUser)(
        issuerTbs,
        tbsModulusOffset,
        tbsModulusTagOffset
    ) ==> userRsaExtractedModulus;

    // ── Step 9: Verify issuer RSA-SHA256 signature over issuerTbs ───────
    CertRSA256Verify(maxMessageLength, n, kIssuer)(
        issuerTbs,
        issuerTbsLength,
        issuerRsaModulus,
        issuerRsaSignature
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
    // Sized to kUser so pkCommit byte-matches UserSigRSA256's output.
    component pkHash = ChunkedPoseidonP256(kUser + 1);
    for (var i = 0; i < kUser; i++) {
        pkHash.inputs[i] <== userRsaExtractedModulus[i];
    }
    pkHash.inputs[kUser] <== pkBlind;
    pkCommit <== pkHash.out;
}
