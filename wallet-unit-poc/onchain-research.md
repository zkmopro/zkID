# Exploring Spartan2 Proofs for On-Chain Verification

## 1. Motivation

OpenAC requires on-chain verification of anonymous credential proofs. This document explores all options for on-chain verification for OpenAC whether it is possible with the current design or not, and if it is expensive, at what cost.

### Properties We Do Not Want to Compromise On

1. Rerandomizable proofs
2. Transparent setup
3. Zero knowledge

Any solution should **not** change any of these core properties.

Post-quantum security is a good-to-have property, although we are not discussing it in this section.

### Circuit Size

Before we discuss solutions, note that our circuit size is around 1 million+ constraints (2^20) and the current design uses Hyrax PCS + Spartan2.

---

## 2. Options

### Option 1: Groth16 with the Same R1CS Circuits

Reuse existing circuits, remove the OpenAC layer, add a per-circuit trusted setup.

**Trade-off:** Breaks transparent setup.

---

### Option 2: Spartan2 + SPARK — Native Solidity Verifier

SPARK optimization is **not** implemented in our repo. SPARK is a preprocessing step that reduces the verifier's work on matrix evaluations and eliminates the need to store full R1CS matrices on-chain (~125 MB for a 2^20 circuit).

Spartan2 uses **T256 (secp256r1)** for Hyrax + IPA, and the EVM has no T256 precompile. RIP-7212 / EIP-7951 exposes `ECDSA.verify(hash, r, s, x, y)` for the same curve, but it can't be used for the `ecAdd`/`ecMul`/MSM operations that Hyrax and IPA need — so every curve op has to be implemented in Solidity.

**What SPARK helps:** Makes contract deployment feasible by removing the large matrix storage requirement from the verifier key.

**What it doesn't help:** Per-verification gas cost barely changes (~3.7% savings). The real bottleneck is the T256 elliptic curve operations in Hyrax PCS. SPARK trades cheap field operations for expensive EC operations, so the savings mostly cancel out.

**Estimated cost (as a Solidity contract):** ~200M gas on Arbitrum (~$20) for 2^20 constraints. ~40–80M gas for smaller circuits. Still prohibitively expensive.

---

### Option 3: Spartan2 + SPARK + WHIR — Native On-Chain Verifier

Replace Hyrax PCS with WHIR (a hash-based PCS) and add SPARK preprocessing. Build a Solidity verifier for this system.

| Property | Value |
| --- | --- |
| Proof size | 55–85 KiB |
| Single verification (Arbitrum) | ~$0.08–$0.93 |
| Batched verification (Arbitrum) | ~$0.03–$0.05 |

This option is popular because it offers cheaper on-chain verification and post-quantum security.

**Trade-off:** WHIR is hash-based, which means commitments are no longer additively homomorphic. This **breaks rerandomizable proofs,** we would lose that property.

---

### Option 4: Spartan2 Proof → Groth16 Wrapper

Verify the Spartan proof inside a Groth16 circuit for cheap on-chain verification. Alternatively, use a ZKVM with private proof delegation to convert a Spartan2 proof into a Groth16 proof.

Keeps transparency internally, but the wrapper reintroduces trusted setup. Much slower prover (30–120s) due to recursion.

**Trade-off:** This is a temporary and brute-force solution — it reintroduces a trusted setup, **breaking the transparent setup property**.

---

### Option 5: Spartan2 + KZG

Replace Hyrax PCS with KZG inside the existing Spartan2 codebase.

**Does it exist?** Yes. Spartan is designed to work with any polynomial commitment scheme. KZG variants exist HyperKZG (used in Nova/SuperNova) is exactly this. Spartan2 codebase doesn't have this implementation yet.

| Property | Value |
| --- | --- |
| On-chain verification gas | ~200–300K |
| Compared to Hyrax | 40–80M+ gas |
| Rerandomization | Preserved (KZG is additively homomorphic) |
| ZK | Preserved |

**Trade-off:** We lose transparent setup (KZG needs a trusted setup / universal SRS), but gain constant-size proofs and dramatically cheaper on-chain verification.

---

### Option 6: Arbitrum Stylus Verifier (Rust → WASM)

**Deployed to Arbitrum Sepolia testnet:** [0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd](https://sepolia.arbiscan.io/address/0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd#code)

Since no L2 provides a T256 precompile (and RIP-7212 only exposes ECDSA `verify`, not the `ecAdd`/`ecMul`/MSM that Hyrax and IPA need), the next best option is **Arbitrum Stylus**, which runs a WASM VM alongside the EVM with ~10–100× cheaper compute for cryptographic operations. I built a fully self-contained Spartan2 verifier targeting Stylus, with custom T256 field and curve arithmetic, no external crypto dependencies, compiled to WASM and deployed on Arbitrum Sepolia.

This approach sidesteps the precompile problem entirely: instead of waiting for chains to add P-256 `ecAdd`/`ecMul` support, all curve arithmetic runs natively in WASM at Stylus gas rates. It preserves all three core properties — transparent setup, rerandomizable proofs, and zero knowledge.

| Property | Value |
| --- | --- |
| Estimated gas (CubicCircuit, ~1k constraints) | ~3–10M (vs. ~60–100M Solidity) |
| WASM size (current build, uncompressed) | ~349 KB |
| Stylus brotli size cap | 24 KB |
| Rerandomization | Preserved |
| Transparent setup | Preserved |

**Open blocker — contract size.** Stylus caps contracts at 24 KB brotli-compressed. The current build is ~349 KB uncompressed, well over the limit. Mitigations under investigation: `wasm-opt -Oz`, splitting the verifier across a router + sumcheck + PCS contracts via `delegatecall`, and trimming unused curve code. The deployed contract uses a chunked-contract pattern as a workaround.

_**Current progress:** Deployed contract using a chunked contract pattern, but the RPC client is rejecting the ~100 KB calldata. Currently investigating workarounds to submit the transaction, and if successful, measuring the actual on-chain verification cost on testnet._

---

## 3. Summary

| Option | Transparent Setup | Rerandomizable | ZK | On-Chain Cost | Notes |
| --- | --- | --- | --- | --- | --- |
| 1. Groth16 | No | Yes | Yes | ~$0.003 | Cheapest, but trusted setup |
| 2. Spartan2 + SPARK (Solidity) | Yes | Yes | Yes | ~$20 | Prohibitively expensive |
| 3. Spartan2 + SPARK + WHIR | Yes | **No** | Yes | ~$0.03–$0.93 | Breaks rerandomization |
| 4. Spartan2 → Groth16 wrapper | No | Yes | Yes | ~$0.003 | Temporary; slow prover (~30–120s) |
| 5. Spartan2 + KZG | No | Yes | Yes | ~$0.01–$0.05 | Cheapest transparent-on-paper option; needs implementation |
| 6. Spartan2 on Arbitrum Stylus | Yes | Yes | Yes | TBD (~3–10M gas est.) | Preserves all properties; blocked on 24 KB WASM size cap |

## 4. Conclusion

Two options preserve all three core properties (rerandomizable proofs, transparent setup, and zero knowledge):

- **Option 2 (Spartan2 + SPARK as a Solidity contract)** is the textbook approach but prohibitively expensive (~$20 per verification on Arbitrum) because the EVM has no T256 precompile, so every Hyrax/IPA elliptic-curve op runs as Solidity bytecode.
- **Option 6 (Spartan2 on Arbitrum Stylus)** is the approach this repo investigates. Stylus runs the verifier as WASM at ~10–100× cheaper compute, which is what makes T256 arithmetic plausibly affordable on-chain. The estimated cost for a small circuit is ~3–10M gas vs. ~60–100M for the equivalent Solidity verifier. The open blocker is the 24 KB Stylus brotli size cap — the current build is ~349 KB and needs aggressive size optimization (`wasm-opt -Oz`, contract splitting via `delegatecall`, dead-code elimination) before the on-chain cost can actually be measured.

Every other option compromises at least one core property:

- **Options 1, 4, and 5** sacrifice transparent setup (trusted setup required).
- **Option 3** sacrifices rerandomizable proofs (WHIR is not additively homomorphic).

If the Stylus size blocker can be resolved, Option 6 is the only path that keeps every property *and* lands at a usable cost. If it cannot, Option 5 (Spartan2 + KZG) is the most pragmatic fallback — losing only transparent setup in exchange for ~$0.01–$0.05 verifications.
