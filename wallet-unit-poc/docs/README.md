# zkID `wallet-unit-poc` docs

Design and planning documents for the wallet-unit-poc stack (circom circuits,
ecdsa-spartan2 Rust prover, spartan2-wasm / web prover, mobile bindings,
TypeScript SDK).

## Architecture

- [`web-prover-architecture.md`](./web-prover-architecture.md) — End-to-end design
  of the in-browser zkID prover: spartan2-wasm crate, the `/` and `/prove`
  two-route COOP split, OPFS asset cache, HiPKI popupForm bridge, local SMT
  rebuild, server-side verification via go-zkid-verifier, and the drift guards
  that keep the browser and native paths byte-identical.

## Active plans

- [`circuit-rust-optimization.md`](./circuit-rust-optimization.md) — Circuit
  constraint reduction and Rust prover optimization plan on
  `refactor/circuit-optimization`. Covers CI split, rebase onto main (absorbing
  PR #23), `VerifySubjectDN` / `VerifySerialNumber` redesign with zk-email's
  `SelectSubArray`, and prover-side wins including skipping R1CS load during
  prove.
