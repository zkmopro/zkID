pragma circom 2.2.3;

include "rs256.circom";
include "components/pkCommit.circom";

/// @title UserSigRSA256
/// @notice Circuit B of the CertChain + UserSig pair. Verifies an RSA
///         signature over the SHA-256-padded `tbs` and emits `pkCommit`,
///         `nullifier = ChunkedPoseidonP256(signature)`, and `appIdPacked`
///         (`tbs[0..31]` packed into one field element).
///
///         `challenge` is a per-session field element issued by the verifier,
///         bound into the proof via a Semaphore-style dummy square
///         (https://github.com/semaphore-protocol/semaphore/blob/341475c66bee7473f8d25f44bc0dcf6b255b5a6c/packages/circuits/src/semaphore.circom#L74).
///         Together with the verifier's per-session TTL on `challenge_id`,
///         this prevents pre-generated proofs from being replayed.
///
/// @param maxMessageLength  Max byte length of `tbs` (1536)
/// @param n                 RSA limb bits (e.g. 121)
/// @param k                 RSA limb count (17 for 2048-bit, 34 for 4096-bit)
template UserSigRSA256(maxMessageLength, n, k) {
    signal input tbs[maxMessageLength];

    signal input userPkLimbs[k];
    signal input userRsaSignature[k];

    // Must match CertChainRSA256's pkBlind.
    signal input pkBlind;

    // Per-session nonce from the verifier's /challenge endpoint.
    signal input challenge;

    signal output pkCommit;
    signal output nullifier;
    signal output appIdPacked;

    // Canonical SHA-256 padding for a 31-byte app_id_bytes:
    //   tbs[31]     = 0x80                    (padding marker)
    //   tbs[32..63] = 0                       (31 zero bytes filling the gap)
    //   tbs[63]     = 0xF8                    (LSB of 64-bit length: 31*8 = 248)
    //   tbs[64..]   = 0                       (forced by AssertZeroPadding in CertRSA256Verify)
    // Pinning the padded length to 64 and the padding bytes to their canonical
    // values forces `tbs` to be a deterministic function of tbs[0..31] = app_id,
    // so σ = sign(SHA256(app_id)) is determined by (card, app_id) and
    // nullifier = Hash(σ) is per-(card, app_id) unique. Closes audit v2
    // Finding 2 (Sybil bypass via nullifier malleability).
    tbs[31] === 0x80;
    for (var i = 32; i < 63; i++) {
        tbs[i] === 0;
    }
    tbs[63] === 0xF8;

    CertRSA256Verify(maxMessageLength, n, k)(
        tbs,
        64,
        userPkLimbs,
        userRsaSignature
    );

    // Pack tbs[0..31] little-endian into one field element. Byte-range of
    // tbs[i] is already enforced inside CertRSA256Verify (Num2Bits(8) on the
    // message), so no extra range checks are needed.
    component appIdPacker = PackBytes(31, maxMessageLength);
    for (var i = 0; i < maxMessageLength; i++) {
        appIdPacker.in[i] <== tbs[i];
    }
    appIdPacked <== appIdPacker.out[0];

    // Semaphore-style dummy square: binds `challenge` into the constraint
    // system without it entering pkCommit or the nullifier.
    signal challengeSquared;
    challengeSquared <== challenge * challenge;

    component pkHash = ChunkedPoseidonP256(k + 1);
    for (var i = 0; i < k; i++) {
        pkHash.inputs[i] <== userPkLimbs[i];
    }
    pkHash.inputs[k] <== pkBlind;
    pkCommit <== pkHash.out;

    component nullifierHash = ChunkedPoseidonP256(k);
    for (var i = 0; i < k; i++) {
        nullifierHash.inputs[i] <== userRsaSignature[i];
    }
    nullifier <== nullifierHash.out;
}
