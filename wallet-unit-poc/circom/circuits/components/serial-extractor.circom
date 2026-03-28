pragma circom 2.2.3;

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";

/// @title DERSerialExtractor
/// @notice Extracts a serial number from a DER-encoded INTEGER field in a certificate
/// @dev    DER INTEGER layout: 0x02 (tag) | length | value bytes
///         Prover supplies serialOffset pointing to the 0x02 tag byte,
///         and serialLength indicating how many value bytes to read.
///         Circuit validates the INTEGER tag, extracts up to maxSerialLen bytes,
///         and packs them big-endian into a single field element.
/// @param maxLen        Maximum certificate DER byte length
/// @param maxSerialLen  Maximum serial number byte length (e.g. 16 for 128-bit)
/// @input in            Certificate DER bytes, zero-padded to maxLen
/// @input serialOffset  Byte offset of the 0x02 INTEGER tag in `in`
/// @input serialLength  Number of serial number value bytes (excluding tag + length)
/// @output serialNumber Packed field element (big-endian) of the serial number
template DERSerialExtractor(maxLen, maxSerialLen) {
    signal input in[maxLen];
    signal input serialOffset;
    signal input serialLength;
    signal output serialNumber;

    // ── Step 1: Validate INTEGER tag (0x02) at serialOffset ──────────────
    component tagSel = Multiplexer(1, maxLen);
    for (var i = 0; i < maxLen; i++) {
        tagSel.inp[i][0] <== in[i];
    }
    tagSel.sel <== serialOffset;
    tagSel.out[0] === 2;  // 0x02 = INTEGER tag

    // ── Step 2: Extract maxSerialLen bytes starting at serialOffset + 2 ──
    // (skip tag byte + 1-byte length field)
    component bytesel[maxSerialLen];
    component ltn[maxSerialLen];
    signal rawBytes[maxSerialLen];

    for (var i = 0; i < maxSerialLen; i++) {
        // Check that index i is within serialLength
        ltn[i] = LessThan(12);
        ltn[i].in[0] <== i;
        ltn[i].in[1] <== serialLength;

        bytesel[i] = Multiplexer(1, maxLen);
        for (var j = 0; j < maxLen; j++) {
            bytesel[i].inp[j][0] <== in[j];
        }
        bytesel[i].sel <== serialOffset + 2 + i;

        // Zero out bytes beyond serialLength
        rawBytes[i] <== bytesel[i].out[0] * ltn[i].out;
    }

    // ── Step 3: Pack bytes big-endian into a single field element ────────
    // serialNumber = sum(rawBytes[i] * 256^(maxSerialLen-1-i))
    signal acc[maxSerialLen + 1];
    acc[0] <== 0;
    for (var i = 0; i < maxSerialLen; i++) {
        acc[i + 1] <== acc[i] * 256 + rawBytes[i];
    }
    serialNumber <== acc[maxSerialLen];
}
