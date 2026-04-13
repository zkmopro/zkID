pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/poseidon.circom";


template VerifyTBSinCert(MAX_CERT_LEN, MAX_TBS_LEN) {
    var TBS_OFFSET = 4;

    signal input user_cert[MAX_CERT_LEN];
    signal input tbs[MAX_TBS_LEN];
    signal input issuer_tbs_length;          // actual length, runtime

    component isLt[MAX_TBS_LEN];
    signal diff[MAX_TBS_LEN];

    for (var i = 0; i < MAX_TBS_LEN - TBS_OFFSET; i++) {
        isLt[i] = LessThan(12);
        isLt[i].in[0] <== i;
        isLt[i].in[1] <== issuer_tbs_length;

        // only enforce if i < issuer_tbs_length
        // (user_cert[4+i] - tbs[i]) * isLt[i].out === 0
        diff[i] <== user_cert[TBS_OFFSET + i] - tbs[i];
        diff[i] * isLt[i].out === 0;
    }
}

template VerifySubjectDN(MAX_CERT_LEN, MAX_SUBJECT_LEN) {
    signal input cert[MAX_CERT_LEN];
    signal input subject_dn[MAX_SUBJECT_LEN];
    signal input subject_dn_offset;
    signal input length;

    // Step 1: extract cert[subject_dn_offset + i] for each i
    // One selector per output byte — O(MAX_SUBJECT_LEN * MAX_CERT_LEN)
    // but MAX_SUBJECT_LEN is small (~100) so total is manageable

    signal selected[MAX_SUBJECT_LEN][MAX_CERT_LEN];
    signal sums[MAX_SUBJECT_LEN][MAX_CERT_LEN + 1];
    signal cert_byte[MAX_SUBJECT_LEN];
    component isEq[MAX_SUBJECT_LEN][MAX_CERT_LEN];
    component isLt[MAX_SUBJECT_LEN];

    for (var i = 0; i < MAX_SUBJECT_LEN; i++) {
        sums[i][0] <== 0;
        for (var j = 0; j < MAX_CERT_LEN; j++) {
            isEq[i][j] = IsEqual();
            isEq[i][j].in[0] <== j;
            isEq[i][j].in[1] <== subject_dn_offset + i;  // target index
            selected[i][j] <== cert[j] * isEq[i][j].out;
            sums[i][j+1] <== sums[i][j] + selected[i][j];
        }
        cert_byte[i] <== sums[i][MAX_CERT_LEN];

        // Step 2: enforce match only for i < length
        isLt[i] = LessThan(12);
        isLt[i].in[0] <== i;
        isLt[i].in[1] <== length;
        (cert_byte[i] - subject_dn[i]) * isLt[i].out === 0;

        // enforce zero-padding when i >= length
        subject_dn[i] * (1 - isLt[i].out) === 0;
    }
}

// Extracts bytes at [offset .. offset+length] and reconstructs
// them as a big-endian integer, then checks it equals target
template VerifySerialNumber(MAX_CERT_LEN, MAX_SERIAL_LEN) {
    signal input cert[MAX_CERT_LEN];
    signal input offset;
    signal input target;  // single big-endian integer

    // -----------------------------------------------------------------------
    // Step 0: Extract tag byte at (offset-2) and length byte at (offset-1)
    // -----------------------------------------------------------------------
    component tagEq[MAX_CERT_LEN];
    component lenEq[MAX_CERT_LEN];
    signal tagSelected[MAX_CERT_LEN];
    signal lenSelected[MAX_CERT_LEN];
    signal tagSum[MAX_CERT_LEN + 1];
    signal lenSum[MAX_CERT_LEN + 1];

    tagSum[0] <== 0;
    lenSum[0] <== 0;
    for (var j = 0; j < MAX_CERT_LEN; j++) {
        tagEq[j] = IsEqual();
        tagEq[j].in[0] <== j;
        tagEq[j].in[1] <== offset - 2;
        tagSelected[j] <== cert[j] * tagEq[j].out;
        tagSum[j+1] <== tagSum[j] + tagSelected[j];

        lenEq[j] = IsEqual();
        lenEq[j].in[0] <== j;
        lenEq[j].in[1] <== offset - 1;
        lenSelected[j] <== cert[j] * lenEq[j].out;
        lenSum[j+1] <== lenSum[j] + lenSelected[j];
    }

    // Enforce ASN.1 INTEGER tag == 0x02
    component tagCheck = IsEqual();
    tagCheck.in[0] <== tagSum[MAX_CERT_LEN];
    tagCheck.in[1] <== 2;
    tagCheck.out === 1;

    // Extract actual length and enforce 1 <= actual_len <= MAX_SERIAL_LEN
    signal actual_len;
    actual_len <== lenSum[MAX_CERT_LEN];

    component lenGtZero = GreaterThan(8);
    lenGtZero.in[0] <== actual_len;
    lenGtZero.in[1] <== 0;
    lenGtZero.out === 1;

    component lenInRange = LessEqThan(8);
    lenInRange.in[0] <== actual_len;
    lenInRange.in[1] <== MAX_SERIAL_LEN;
    lenInRange.out === 1;

    // -----------------------------------------------------------------------
    // Step 1: Extract raw serial bytes at cert[offset + i]
    // -----------------------------------------------------------------------
    component isEq[MAX_SERIAL_LEN][MAX_CERT_LEN];
    signal selected[MAX_SERIAL_LEN][MAX_CERT_LEN];
    signal sums[MAX_SERIAL_LEN][MAX_CERT_LEN + 1];
    signal raw_bytes[MAX_SERIAL_LEN];

    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        sums[i][0] <== 0;
        for (var j = 0; j < MAX_CERT_LEN; j++) {
            isEq[i][j] = IsEqual();
            isEq[i][j].in[0] <== j;
            isEq[i][j].in[1] <== offset + i;
            selected[i][j] <== cert[j] * isEq[i][j].out;
            sums[i][j+1] <== sums[i][j] + selected[i][j];
        }
        raw_bytes[i] <== sums[i][MAX_CERT_LEN];
    }

    // -----------------------------------------------------------------------
    // Step 2: Zero-mask bytes at index >= actual_len
    // -----------------------------------------------------------------------
    component iLt[MAX_SERIAL_LEN];
    signal masked_bytes[MAX_SERIAL_LEN];

    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        iLt[i] = LessThan(8);
        iLt[i].in[0] <== i;
        iLt[i].in[1] <== actual_len;
        masked_bytes[i] <== raw_bytes[i] * iLt[i].out;
    }

    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Step 3: Reconstruct big-endian integer using actual_len-relative powers
    // -----------------------------------------------------------------------

    // Precompute compile-time power table: pow256[k] = 256^k
    var pow256[MAX_SERIAL_LEN + 1];
    pow256[0] = 1;
    for (var k = 1; k <= MAX_SERIAL_LEN; k++) {
        pow256[k] = pow256[k-1] * 256;
    }

    // For each byte i, its weight is 256^(actual_len - 1 - i)
    // = pow256[actual_len - 1 - i]
    // Since actual_len is a signal (dynamic), select from pow256 table dynamically.
    // weight[i] = sum over k of (pow256[k] * IsEqual()(actual_len - 1 - i, k))
    //           = sum over k of (pow256[k] * IsEqual()(actual_len, k + 1 + i))

    component powEq[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSelected[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSum[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 2];
    signal byte_weight[MAX_SERIAL_LEN];

    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        powSum[i][0] <== 0;
        for (var k = 0; k <= MAX_SERIAL_LEN; k++) {
            powEq[i][k] = IsEqual();
            powEq[i][k].in[0] <== actual_len;
            powEq[i][k].in[1] <== k + 1 + i;  // actual_len == k+1+i means weight is 256^k
            powSelected[i][k] <== pow256[k] * powEq[i][k].out;
            powSum[i][k+1] <== powSum[i][k] + powSelected[i][k];
        }
        byte_weight[i] <== powSum[i][MAX_SERIAL_LEN + 1];
    }

    // weighted[i] = masked_bytes[i] * 256^(actual_len - 1 - i)
    signal weighted[MAX_SERIAL_LEN];
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        weighted[i] <== masked_bytes[i] * byte_weight[i];
    }

    signal reconSum[MAX_SERIAL_LEN + 1];
    reconSum[0] <== 0;
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        reconSum[i+1] <== reconSum[i] + weighted[i];
    }

    reconSum[MAX_SERIAL_LEN] === target;
}

/// @title ExtractModulus
/// @notice Extracts an RSA public key modulus from a DER-encoded certificate
/// @dev    SubjectPublicKeyInfo layout:
///           SEQUENCE {
///             SEQUENCE { OID rsaEncryption  NULL }
///             BIT STRING {
///               SEQUENCE {
///                 INTEGER  ← modulus value bytes start at modulusOffset
///                 INTEGER  ← exponent (65537)
///               }
///             }
///           }
///         Prover supplies modulusTagOffset pointing to the 0x02 INTEGER tag
///         and modulusOffset pointing to the first actual modulus byte
///         (after tag + length field + optional 0x00 sign byte).
///         Circuit validates the INTEGER tag at modulusTagOffset.
///         DER is big-endian; limbs are packed LSB-first for RSAVerifier65537.
///         For non-byte-aligned limb sizes (e.g. n=121), bits beyond
///         modulusBits in the top limb are zero-padded.
/// @param maxLen        Maximum certificate DER byte length
/// @param n             Bits per RSA limb (e.g. 121)
/// @param k             Number of RSA limbs (e.g. 17 for RSA-2048)
/// @param modulusBits   Actual RSA key size in bits (e.g. 2048) — must be
///                      divisible by 8. Separate from n*k (e.g. 121*17=2057).
/// @input in                Certificate DER bytes, zero-padded to maxLen
/// @input modulusOffset     Byte offset of first modulus value byte in `in`
///                          (points past tag + length field + sign byte)
/// @input modulusTagOffset  Byte offset of the INTEGER tag (0x02) in `in`
///                          Circuit asserts in[modulusTagOffset] == 2
/// @output out              Modulus as k limbs of n bits, LSB limb first
///                          Compatible with RSAVerifier65537(n, k)
template ExtractModulus(maxLen, n, k, modulusBits) {
    var modulusBytes = modulusBits \ 8;  // 2048\8 = 256 bytes

    signal input in[maxLen];
    signal input modulusOffset;
    signal input modulusTagOffset;
    signal output out[k];

    // ── Step 1: Validate INTEGER tag (0x02) at modulusTagOffset ──────────
    // Prevents prover from pointing at arbitrary bytes as the modulus
    component tagSel = Multiplexer(1, maxLen);
    for (var i = 0; i < maxLen; i++) {
        tagSel.inp[i][0] <== in[i];
    }
    tagSel.sel <== modulusTagOffset;
    tagSel.out[0] === 2;  // 0x02 = INTEGER tag

    // ── Step 2: Extract modulusBytes bytes starting at modulusOffset ──────
    // Uses clamped selector to avoid Multiplexer out-of-bounds assert
    component bytesel[modulusBytes];
    component ltn[modulusBytes];
    signal modBytes[modulusBytes];

    for (var i = 0; i < modulusBytes; i++) {
        // Check modulusOffset + i is within maxLen
        ltn[i] = LessThan(12);
        ltn[i].in[0] <== modulusOffset + i;
        ltn[i].in[1] <== maxLen;

        bytesel[i] = Multiplexer(1, maxLen);
        for (var j = 0; j < maxLen; j++) {
            bytesel[i].inp[j][0] <== in[j];
        }
        // Clamp selector: use modulusOffset+i if in bounds, else 0
        bytesel[i].sel <== ltn[i].out * (modulusOffset + i) +
                           (1 - ltn[i].out) * 0;

        // Zero out if out of bounds
        modBytes[i] <== bytesel[i].out[0] * ltn[i].out;
    }

    // ── Step 3: Bytes → flat bit array (MSB first) ────────────────────────
    // modBytes[0] is the most significant byte (big-endian DER)
    // bits[0] = MSB of modBytes[0], bits[modulusBits-1] = LSB of last byte
    component byte2bits[modulusBytes];
    signal bits[modulusBytes * 8];  // = modulusBits bits

    for (var i = 0; i < modulusBytes; i++) {
        byte2bits[i] = Num2Bits(8);
        byte2bits[i].in <== modBytes[i];
        for (var j = 0; j < 8; j++) {
            bits[i * 8 + j] <== byte2bits[i].out[7 - j];  // MSB first
        }
    }

    // ── Step 4: Pack bits → k limbs of n bits, LSB limb first ────────────
    // bits[0]          = MSB of modulus
    // bits[modulusBits-1] = LSB of modulus
    //
    // limb[0] = least significant n bits of modulus
    // limb[k-1] = most significant n bits of modulus
    //
    // For i-th limb, j-th bit:
    //   bitPos = i*n + j  (position from LSB end)
    //   maps to bits[modulusBits - 1 - bitPos]
    //
    // If bitPos >= modulusBits (top limb overflow when n*k > modulusBits),
    //   zero-pad those bits
    component b2n[k];

    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitPos = i * n + j;
            if (bitPos < modulusBits) {
                b2n[i].in[j] <== bits[modulusBits - 1 - bitPos];
            } else {
                // Zero-pad top limb bits that exceed modulusBits
                // e.g. n=121, k=17: n*k=2057 but modulusBits=2048
                // limb[16] bits 2048..2056 are zero
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

template PackBytes(N_BYTES, TBS_LENGTH) {
    // packs N_BYTES into ceil(N_BYTES/31) field elements
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[TBS_LENGTH];
    signal output out[N_FIELDS];

    for (var f = 0; f < N_FIELDS; f++) {
        var acc = 0;
        var shift = 1;
        for (var i = 0; i < BYTES_PER_FIELD; i++) {
            var idx = f * BYTES_PER_FIELD + i;
            if (idx < N_BYTES) {
                acc = acc + in[idx] * shift;
            }
            shift = shift * 256;
        }
        out[f] <== acc;
    }
}

template PoseidonBytes(N_BYTES) {
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[N_BYTES];
    signal output out;

    // step 1: pack bytes → field elements
    component packer = PackBytes(N_BYTES, N_BYTES);
    for (var i = 0; i < N_BYTES; i++) {
        packer.in[i] <== in[i];
    }

    // step 2: hash packed field elements
    component hasher = Poseidon(N_FIELDS);
    for (var f = 0; f < N_FIELDS; f++) {
        hasher.inputs[f] <== packer.out[f];
    }

    out <== hasher.out;
}
