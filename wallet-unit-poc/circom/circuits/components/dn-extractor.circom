pragma circom 2.2.3;

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";

/// @title ExtractSubjectDN
/// @notice Extracts Subject Distinguished Name bytes from a DER-encoded certificate
/// @dev    DER SEQUENCE layout: 0x30 (tag) | length | value bytes
///         Prover supplies dnOffset pointing to the 0x30 tag byte,
///         and dnLength indicating how many value bytes to extract.
///         Circuit validates the SEQUENCE tag, extracts up to maxDNLen bytes
///         starting at dnOffset + 2 (skip tag + 1-byte length), and zeros
///         bytes beyond dnLength.
/// @param maxLen    Maximum certificate DER byte length
/// @param maxDNLen  Maximum Subject DN byte length to extract
/// @input in        Certificate DER bytes, zero-padded to maxLen
/// @input dnOffset  Byte offset of the 0x30 SEQUENCE tag in `in`
/// @input dnLength  Number of DN value bytes to extract (excluding tag + length)
/// @output dn       Extracted DN bytes, zero-padded to maxDNLen
/// @output dnLen    Actual number of extracted bytes (echoes dnLength)
template ExtractSubjectDN(maxLen, maxDNLen) {
    signal input in[maxLen];
    signal input dnOffset;
    signal input dnLength;
    signal output dn[maxDNLen];
    signal output dnLen;

    // ── Step 1: Validate SEQUENCE tag (0x30) at dnOffset ─────────────────
    component tagSel = Multiplexer(1, maxLen);
    for (var i = 0; i < maxLen; i++) {
        tagSel.inp[i][0] <== in[i];
    }
    tagSel.sel <== dnOffset;
    tagSel.out[0] === 0x30;  // 0x30 = SEQUENCE tag

    // ── Step 2: Extract maxDNLen bytes starting at dnOffset + 2 ──────────
    // (skip tag byte + 1-byte length field)
    component bytesel[maxDNLen];
    component ltn[maxDNLen];

    for (var i = 0; i < maxDNLen; i++) {
        // Check that index i is within dnLength
        ltn[i] = LessThan(12);
        ltn[i].in[0] <== i;
        ltn[i].in[1] <== dnLength;

        bytesel[i] = Multiplexer(1, maxLen);
        for (var j = 0; j < maxLen; j++) {
            bytesel[i].inp[j][0] <== in[j];
        }
        bytesel[i].sel <== dnOffset + 2 + i;

        // Zero out bytes beyond dnLength
        dn[i] <== bytesel[i].out[0] * ltn[i].out;
    }

    // ── Step 3: Output actual length ─────────────────────────────────────
    dnLen <== dnLength;
}
