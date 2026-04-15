# zkID `wallet-unit-poc` docs

Design and planning documents for the wallet-unit-poc stack (circom circuits, ecdsa-spartan2 Rust prover, mobile bindings, TypeScript SDK).

## Current plans

- [`circuit-rust-optimization.md`](./circuit-rust-optimization.md) — Active plan for circuit constraint reduction and Rust prover optimization on `refactor/circuit-optimization`. Covers CI split, rebase onto main (absorbing PR #23), `VerifySubjectDN`/`VerifySerialNumber` redesign with zk-email's `SelectSubArray`, and prover-side wins including skipping R1CS load during prove.
