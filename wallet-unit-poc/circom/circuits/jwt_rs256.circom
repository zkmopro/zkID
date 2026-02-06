pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "components/claim-decoder.circom";
include "components/payload_matcher.circom";
include "components/age-verifier.circom";
include "jwt_tx_builder/header-payload-extractor.circom";

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

/// @title JWTRS256
/// @notice Single-stage RS256 JWT verification circuit with age verification
/// @notice Combines RSA signature verification, claim extraction, and age check
/// @param maxMessageLength Maximum JWT message bytes (header.payload)
/// @param maxB64PayloadLength Maximum base64url payload bytes
/// @param maxMatches Maximum number of claim matches
/// @param maxSubstringLength Maximum substring length for matching
/// @param maxClaimsLength Maximum encoded claim length
/// @param n RSA chunk bits (121 recommended)
/// @param k RSA chunks (17 for 2048-bit keys)
template JWTRS256(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength,
    n,
    k
) {
    var decodedLen = (maxClaimsLength * 3) / 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) / 4;

    // === JWT Message Inputs ===
    signal input message[maxMessageLength];    // header.payload (ASCII bytes)
    signal input messageLength;
    signal input periodIndex;                  // Position of '.' separator

    // === RSA Signature Inputs ===
    signal input rsaModulus[k];                // RSA public key modulus (k limbs)
    signal input rsaSignature[k];              // RSA signature (k limbs)

    // === Claim Matching Inputs ===
    signal input matchesCount;
    signal input matchSubstring[maxMatches][maxSubstringLength];
    signal input matchLength[maxMatches];
    signal input matchIndex[maxMatches];

    // === Selective Disclosure Inputs ===
    signal input claims[maxMatches][maxClaimsLength];
    signal input claimLengths[maxMatches];
    signal input decodeFlags[maxMatches];
    signal input ageClaimIndex;

    // === Date Inputs for Age Verification ===
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    // === Outputs ===
    signal output ageAbove18;

    // --- Step 1: Assert message constraints ---
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // --- Step 2: SHA-256 hash of message ---
    // The SHA256 output is 256 bits in big-endian bit order
    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // --- Step 3: Convert SHA-256 bits to k limbs for RSA verification ---
    // RSA expects the message hash as k limbs of n bits each
    // SHA-256 outputs bits in big-endian order: sha[0] is MSB
    // We need to reverse to little-endian for RSA limb conversion
    signal shaReversed[256];
    for (var i = 0; i < 256; i++) {
        shaReversed[i] <== sha[255 - i];
    }

    component hashToLimbs = Bits2Limbs(256, n, k);
    hashToLimbs.in <== shaReversed;

    // --- Step 4: RSA Signature Verification ---
    component rsaVerifier = RSAVerifier65537(n, k);
    rsaVerifier.modulus <== rsaModulus;
    rsaVerifier.signature <== rsaSignature;
    rsaVerifier.message <== hashToLimbs.out;

    // --- Step 5: Decode claims and hash them ---
    signal decodedClaims[maxMatches][decodedLen] <== ClaimDecoder(maxMatches, maxClaimsLength)(claims, claimLengths, decodeFlags);
    signal claimHashes[maxMatches][32] <== ClaimHasher(maxMatches, maxClaimsLength)(claims);

    // Compare the claim hashes with the match substrings
    ClaimComparator(maxMatches, maxSubstringLength)(claimHashes, claimLengths, matchSubstring, matchLength);

    // --- Step 6: Extract the payload ---
    signal payload[maxPayloadLength] <== PayloadExtractor(maxMessageLength, maxB64PayloadLength)(
        message,
        messageLength,
        periodIndex
    );

    // --- Step 7: Check if the match substrings are in the payload ---
    signal payloadHash <== PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength)(
        payload,
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex
    );

    // --- Step 8: Select the age claim ---
    component ageSelector = Multiplexer(decodedLen, maxMatches);
    ageSelector.sel <== ageClaimIndex;
    ageSelector.inp <== decodedClaims;

    // --- Step 9: Age Verification ---
    component ageVerifier = AgeVerifier(decodedLen);
    ageVerifier.claim <== ageSelector.out;
    ageVerifier.currentYear <== currentYear;
    ageVerifier.currentMonth <== currentMonth;
    ageVerifier.currentDay <== currentDay;
    ageAbove18 <== ageVerifier.ageAbove18;
}
