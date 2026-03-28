pragma circom 2.2.3;

include "dn-extractor.circom";
include "poseidon_p256.circom";

/// @title DNNullifierTest
/// @notice Test wrapper: extracts DN and computes Poseidon nullifier
/// @param maxLen   Maximum certificate byte length
/// @param maxDNLen Maximum DN byte length to extract
template DNNullifierTest(maxLen, maxDNLen) {
    signal input in[maxLen];
    signal input dnOffset;
    signal input dnLength;
    signal output nullifier;

    // Extract DN
    signal extractedDN[maxDNLen];
    signal extractedDNLen;
    ExtractSubjectDN(maxLen, maxDNLen)(
        in       <== in,
        dnOffset <== dnOffset,
        dnLength <== dnLength
    ) ==> (extractedDN, extractedDNLen);

    // Pack DN bytes into 9 chunks of 31 bytes each (big-endian)
    var nChunks = 9;  // ceil(256/31) = 9

    signal chunks[nChunks];
    signal chunkAcc[nChunks][32];  // [chunk_index][accumulator_step]
    for (var c = 0; c < nChunks; c++) {
        chunkAcc[c][0] <== 0;
        for (var j = 0; j < 31; j++) {
            var byteIdx = c * 31 + j;
            if (byteIdx < maxDNLen) {
                chunkAcc[c][j + 1] <== chunkAcc[c][j] * 256 + extractedDN[byteIdx];
            } else {
                chunkAcc[c][j + 1] <== chunkAcc[c][j] * 256;
            }
        }
        chunks[c] <== chunkAcc[c][31];
    }

    // Sequential Poseidon chain
    component posHash[nChunks - 1];
    signal hashChain[nChunks - 1];

    posHash[0] = PoseidonP256(2);
    posHash[0].inputs[0] <== chunks[0];
    posHash[0].inputs[1] <== chunks[1];
    hashChain[0] <== posHash[0].out;

    for (var i = 1; i < nChunks - 1; i++) {
        posHash[i] = PoseidonP256(2);
        posHash[i].inputs[0] <== hashChain[i - 1];
        posHash[i].inputs[1] <== chunks[i + 1];
        hashChain[i] <== posHash[i].out;
    }

    nullifier <== hashChain[nChunks - 2];
}
