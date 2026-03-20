pragma circom 2.2.3;

include "smt_verifier_p256.circom";

/// @title SMTNonMembershipVerifier
/// @notice Wrapper around SMTVerifierP256 that hardcodes non-membership semantics
/// @param depth Number of levels in the Sparse Merkle Tree
template SMTNonMembershipVerifier(depth) {
    signal input root;
    signal input key;
    signal input siblings[depth];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    component verifier = SMTVerifierP256(depth);
    verifier.enabled <== 1;
    verifier.root <== root;
    verifier.siblings <== siblings;
    verifier.oldKey <== oldKey;
    verifier.oldValue <== oldValue;
    verifier.isOld0 <== isOld0;
    verifier.key <== key;
    verifier.value <== 0;   // non-membership: value must be 0
    verifier.fnc <== 1;     // fnc=1: verify non-inclusion
}
