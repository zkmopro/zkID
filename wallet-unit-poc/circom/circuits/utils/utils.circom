pragma circom 2.2.3;

include "../jwt_tx_builder/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "@zk-email/circuits/lib/base64.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";


template Selector() {
    signal input condition;
    signal input in[2];
    signal output out;

    out <== condition * (in[0] - in[1]) + in[1];
}


template DecodeSD(maxSdLen, byteLength) {
    var charLength = 4 * ((byteLength + 2) \ 3);

    signal input sdBytes[maxSdLen];
    signal input sdLen;

    signal stdB64[charLength];
    component inRange[charLength];
    component isDash[charLength];
    component isUnder[charLength];
    component dashSel[charLength];
    component underSel[charLength];
    component rangeSel[charLength];

    for (var i = 0; i < charLength; i++) {

        inRange[i] = LessThan(8);
        inRange[i].in[0] <== i;
        inRange[i].in[1] <== sdLen;

        isDash[i]  = IsEqual();
        isDash[i].in[0] <== sdBytes[i]; 
        isDash[i].in[1] <== 45;
        
        isUnder[i] = IsEqual();
        isUnder[i].in[0] <== sdBytes[i];
        isUnder[i].in[1] <== 95;

        dashSel[i] = Selector();
        dashSel[i].condition <== isDash[i].out;
        dashSel[i].in[0] <== 43;  // '+'
        dashSel[i].in[1] <== sdBytes[i];

        underSel[i] = Selector();
        underSel[i].condition <== isUnder[i].out;
        underSel[i].in[0] <== 47;  // '/'
        underSel[i].in[1] <== dashSel[i].out;

        rangeSel[i] = Selector();
        rangeSel[i].condition <== inRange[i].out;
        rangeSel[i].in[0] <== underSel[i].out;
        rangeSel[i].in[1] <== 61;   // '='

        stdB64[i] <== rangeSel[i].out;
    }


    signal output base64Out[byteLength];
    
    component base64 = Base64Decode(byteLength);
    base64.in <== stdB64;
    base64Out <== base64.out;
}

template AssertBase64UrlChar() {
    signal input char;
    signal input enabled;

    component isUpperGt = GreaterThan(9);
    isUpperGt.in[0] <== char;
    isUpperGt.in[1] <== 64;

    component isUpperLt = LessThan(9);
    isUpperLt.in[0] <== char;
    isUpperLt.in[1] <== 91;

    signal isUpper <== isUpperGt.out * isUpperLt.out;

    component isLowerGt = GreaterThan(9);
    isLowerGt.in[0] <== char;
    isLowerGt.in[1] <== 96;

    component isLowerLt = LessThan(9);
    isLowerLt.in[0] <== char;
    isLowerLt.in[1] <== 123;

    signal isLower <== isLowerGt.out * isLowerLt.out;

    component isDigitGt = GreaterThan(9);
    isDigitGt.in[0] <== char;
    isDigitGt.in[1] <== 47;

    component isDigitLt = LessThan(9);
    isDigitLt.in[0] <== char;
    isDigitLt.in[1] <== 58;

    signal isDigit <== isDigitGt.out * isDigitLt.out;

    component isDash = IsZero();
    isDash.in <== char - 45;   // '-'

    component isUnder = IsZero();
    isUnder.in <== char - 95;  // '_'

    component isPlus = IsZero();
    isPlus.in <== char - 43;   // '+'

    component isSlash = IsZero();
    isSlash.in <== char - 47;  // '/'

    component isPad = IsZero();
    isPad.in <== char - 61;    // '='

    component upperOrLower = OR();
    upperOrLower.a <== isUpper;
    upperOrLower.b <== isLower;

    component alphaOrDigit = OR();
    alphaOrDigit.a <== upperOrLower.out;
    alphaOrDigit.b <== isDigit;

    component dashOrAlphaNum = OR();
    dashOrAlphaNum.a <== alphaOrDigit.out;
    dashOrAlphaNum.b <== isDash.out;

    component plusOrSlash = OR();
    plusOrSlash.a <== isPlus.out;
    plusOrSlash.b <== isSlash.out;

    component dashPlusSlash = OR();
    dashPlusSlash.a <== dashOrAlphaNum.out;
    dashPlusSlash.b <== plusOrSlash.out;

    component underOrPad = OR();
    underOrPad.a <== isUnder.out;
    underOrPad.b <== isPad.out;

    component allowed = OR();
    allowed.a <== dashPlusSlash.out;
    allowed.b <== underOrPad.out;

    (1 - allowed.out) * enabled === 0;
}

template BytesToNumberBE(numBytes) {
    signal input in[numBytes];
    signal output out;

    signal acc[numBytes + 1];
    acc[0] <== 0;

    for (var i = 0; i < numBytes; i++) {
        acc[i + 1] <== acc[i] * 256 + in[i];
    }

    out <== acc[numBytes];
}

// reduce a 256-bit hash modulo the secp256r1 scalar field order
template HashModScalarField() {
    signal input hash[256];  
    signal output out;       
    
    component hashNum = Bits2Num(256);
    for (var i = 0; i < 256; i++) {
        hashNum.in[i] <== hash[255 - i];
    }
    
    var q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    var qlo = q & ((2 ** 128) - 1);
    var qhi = q >> 128;
    
    // 128 bit each
    signal hashLo <-- hashNum.out & (2 ** (128) - 1);
    signal hashHi <-- hashNum.out >> 128;
    
    component verifyLo = Num2Bits(128);
    verifyLo.in <== hashLo;
    component verifyHi = Num2Bits(128);
    verifyHi.in <== hashHi;
    
    // hash >= q
    component alpha = GreaterThan(129);
    alpha.in[0] <== hashHi;
    alpha.in[1] <== qhi;
    
    component beta = IsEqual();
    beta.in[0] <== hashHi;
    beta.in[1] <== qhi;
    
    component gamma = GreaterEqThan(129);
    gamma.in[0] <== hashLo;
    gamma.in[1] <== qlo;
    
    // hashhi == qhi && ashlo >= qlo
    component betaANDgamma = AND();
    betaANDgamma.a <== beta.out;
    betaANDgamma.b <== gamma.out;
    
    component isHashGteQ = OR();
    isHashGteQ.a <== betaANDgamma.out;
    isHashGteQ.b <== alpha.out;
    
    // If hash >= q, hash - q; else hash
    signal resultLo <== hashLo - isHashGteQ.out * qlo;
    signal resultHi <== hashHi - isHashGteQ.out * qhi;
    
    out <== resultLo + resultHi * (2 ** 128);
}

template ExtractBase64UrlValue(maxPayloadLength, maxValueChars, expectedLength) {
    signal input payload[maxPayloadLength];
    signal input startIndex;
    signal output value[maxValueChars];
    signal output valueLength;

    signal found[maxValueChars + 1];
    found[0] <== 0;

    signal lengthAcc[maxValueChars + 1];
    lengthAcc[0] <== 0;

    signal currentIndex[maxValueChars];
    signal currentChar[maxValueChars];
    signal notFound[maxValueChars];
    signal includeChar[maxValueChars];

    component isQuote[maxValueChars];
    component base64Check[maxValueChars];

    for (var i = 0; i < maxValueChars; i++) {
        currentIndex[i] <== startIndex + i;
        currentChar[i] <== SelectArrayValue(maxPayloadLength)(payload, currentIndex[i], 1);

        isQuote[i] = IsEqual();
        isQuote[i].in[0] <== currentChar[i];
        isQuote[i].in[1] <== 34;

        notFound[i] <== 1 - found[i];
        includeChar[i] <== notFound[i] - notFound[i] * isQuote[i].out;

        base64Check[i] = AssertBase64UrlChar();
        base64Check[i].char <== currentChar[i];
        base64Check[i].enabled <== includeChar[i];

        value[i] <== includeChar[i] * currentChar[i];

        lengthAcc[i + 1] <== lengthAcc[i] + includeChar[i];
        found[i + 1] <== found[i] + isQuote[i].out - found[i] * isQuote[i].out;
    }

    found[maxValueChars] === 1;
    valueLength <== lengthAcc[maxValueChars];

    component lengthCheckExact = IsEqual();
    lengthCheckExact.in[0] <== valueLength;
    lengthCheckExact.in[1] <== expectedLength;

    component lengthCheckOneLess = IsEqual();
    lengthCheckOneLess.in[0] <== valueLength;
    lengthCheckOneLess.in[1] <== expectedLength - 1;

    component lengthOk = OR();
    lengthOk.a <== lengthCheckExact.out;
    lengthOk.b <== lengthCheckOneLess.out;
    lengthOk.out === 1;

    signal closingIndex <== startIndex + valueLength;
    signal closingChar <== SelectArrayValue(maxPayloadLength)(payload, closingIndex, 1);
    closingChar === 34;
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

/// @title Sha256GeneralRaw
/// @notice A modified version of the SHA256 circuit that allows specified length messages up to a 
///         max to all work via array indexing on the SHA256 compression circuit.
/// @input paddedIn Message to hash padded as per the SHA256 specification; assumes to consist of bits
/// @input paddedInLength Length of the padded message; assumes to be in `ceil(log2(maxBitLength))` bits
/// @output out The 256-bit hash of the input message
template Sha256GeneralRaw(maxBitLength) {
    // maxBitLength must be a multiple of 512
    // the bit circuits in this file are limited to 15 so must be raised if the message is longer.
    assert(maxBitLength % 512 == 0);

    var maxBitsPaddedBits = log2Ceil(maxBitLength);

    // Note that maxBitLength = maxBits + 64
    signal input paddedIn[maxBitLength];
    signal input paddedInLength;
    
    signal output out[256];
    
    signal inBlockIndex;

    var i;
    var k;
    var j;
    var maxBlocks;
    var bitsLastBlock;
    maxBlocks = (maxBitLength\512);

    inBlockIndex <-- (paddedInLength >> 9);
    // paddedInLength === inBlockIndex * 512;

    // These verify the unconstrained floor calculation is the uniquely correct integer that represents the floor
    // component floorVerifierUnder = LessEqThan(maxBitsPaddedBits); // todo verify the length passed in is less than nbits. note that maxBitsPaddedBits can likely be lowered or made it a fn of maxbits
    // floorVerifierUnder.in[0] <== (inBlockIndex)*512;
    // floorVerifierUnder.in[1] <== paddedInLength;
    // floorVerifierUnder.out === 1;

    // component floorVerifierOver = GreaterThan(maxBitsPaddedBits);
    // floorVerifierOver.in[0] <== (inBlockIndex+1)*512;
    // floorVerifierOver.in[1] <== paddedInLength;
    // floorVerifierOver.out === 1;

    // These verify we pass in a valid number of bits to the SHA256 compression circuit.
    component bitLengthVerifier = LessEqThan(maxBitsPaddedBits); // todo verify the length passed in is less than nbits. note that maxBitsPaddedBits can likely be lowered or made it a fn of maxbits
    bitLengthVerifier.in[0] <== paddedInLength;
    bitLengthVerifier.in[1] <== maxBitLength;
    bitLengthVerifier.out === 1;

    // Note that we can no longer do padded verification efficiently inside the SHA because it requires non deterministic array indexing.
    // We can do it if we add a constraint, but since guessing a valid SHA2 preimage is hard anyways, we'll just do it outside the circuit.

    // signal paddedIn[maxBlocks*512];
    // for (k=0; k<maxBits; k++) {
    //     paddedIn[k] <== in[k];
    // }
    // paddedIn[maxBits] <== 1;
    // for (k=maxBits+1; k<maxBlocks*512-64; k++) {
    //     paddedIn[k] <== 0;
    // }
    // for (k = 0; k< 64; k++) {
    //     paddedIn[maxBlocks*512 - k -1] <== (maxBits >> k)&1;
    // }

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[maxBlocks];

    for (i=0; i<maxBlocks; i++) {
        sha256compression[i] = Sha256compression() ;

        if (i==0) {
            for (k=0; k<32; k++ ) {
                sha256compression[i].hin[0*32+k] <== ha0.out[k];
                sha256compression[i].hin[1*32+k] <== hb0.out[k];
                sha256compression[i].hin[2*32+k] <== hc0.out[k];
                sha256compression[i].hin[3*32+k] <== hd0.out[k];
                sha256compression[i].hin[4*32+k] <== he0.out[k];
                sha256compression[i].hin[5*32+k] <== hf0.out[k];
                sha256compression[i].hin[6*32+k] <== hg0.out[k];
                sha256compression[i].hin[7*32+k] <== hh0.out[k];
            }
        } else {
            for (k=0; k<32; k++ ) {
                sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
                sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
                sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
                sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
                sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
                sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
                sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
                sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
            }
        }

        for (k=0; k<512; k++) {
            sha256compression[i].inp[k] <== paddedIn[i*512+k];
        }
    }

    // Select the correct compression output for the given length, instead of just the last one.
    component arraySelectors[256];
    for (k=0; k<256; k++) {
        arraySelectors[k] = ItemAtIndex(maxBlocks);
        for (j=0; j<maxBlocks; j++) {
            arraySelectors[k].in[j] <== sha256compression[j].out[k];
        }
        arraySelectors[k].index <== inBlockIndex - 1; // The index is 0 indexed and the block numbers are 1 indexed.
        out[k] <== arraySelectors[k].out;
    }

    // for (k=0; k<256; k++) {
    //     out[k] <== sha256compression[maxBlocks-1].out[k];
    // }
}


/// @title Sha256BytesRaw  
/// @notice SHA-256 of zero-padded raw bytes — handles sha256 padding internally
/// @dev    Converts raw bytes to sha256-padded bits, then runs Sha256General.
///         Input must be zero-padded to maxByteLength.
///         maxByteLength must be a multiple of 64.
/// @input in       Raw bytes zero-padded to maxByteLength
/// @input length   Actual byte length (not padded length)
/// @output out     256-bit SHA-256 hash
template Sha256BytesRaw(maxByteLength) {
    assert(maxByteLength % 64 == 0);

    signal input in[maxByteLength];
    signal input length;
    signal output out[256];

    var maxBits = maxByteLength * 8;

    // ── Step 1: Bytes → bits ──────────────────────────────────────────────
    signal bits[maxBits];
    component n2b[maxByteLength];
    for (var i = 0; i < maxByteLength; i++) {
        n2b[i]    = Num2Bits(8);
        n2b[i].in <== in[i];
        for (var j = 0; j < 8; j++) {
            bits[i * 8 + j] <== n2b[i].out[7 - j];  // MSB first
        }
    }

    // ── Step 2: Sha256GeneralRaw with length in bits ─────────────────────────
    component sha = Sha256GeneralRaw(maxBits);
    sha.paddedIn       <== bits;
    sha.paddedInLength <== length * 8;  // actual length in bits
    out                <== sha.out;
}

/// @title HashAndLimbs
/// @notice SHA-256 hashes zero-padded raw bytes and packs into RSA limbs
template HashAndLimbs(maxLen, n, k) {
    signal input in[maxLen];      // zero-padded raw bytes
    signal input length;          // actual byte length
    signal output out[k];

    // ── SHA-256 with internal padding ─────────────────────────────────────
    signal hash[256];
    component sha = Sha256BytesRaw(maxLen);
    sha.in     <== in;
    sha.length <== length;
    hash       <== sha.out;

    // ── Pack 256 bits → k limbs, LSB first ───────────────────────────────
    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitPos = i * n + j;
            if (bitPos < 256) {
                b2n[i].in[j] <== hash[255 - bitPos];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}