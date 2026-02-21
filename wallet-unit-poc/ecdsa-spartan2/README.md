# ecdsa-spartan2

This crate contains the Spartan-based proving tooling used in the zkID wallet proof of concept.
It exposes a collection of CLI subcommands (under `cargo run --release -- …`) for the
JWT-RS256 single-stage circuit: setup keys, produce proofs, and verify proofs against the
Circom inputs found in `../circom/inputs/jwt_rs256`.

## End-to-end flow

```sh
# 1. Generate setup artifacts (keys stored in ./keys)
RUST_LOG=info cargo run --release -- jwt_rs256 setup --input ../circom/inputs/jwt_rs256/default.json

# 2. Produce the proof
RUST_LOG=info cargo run --release -- jwt_rs256 prove --input ../circom/inputs/jwt_rs256/default.json

# 3. Verify the proof
RUST_LOG=info cargo run --release -- jwt_rs256 verify
```

## Running Benchmarks

```sh
# Run the complete benchmark pipeline (setup, prove, verify with timing)
RUST_LOG=info cargo run --release -- jwt_rs256 benchmark --input ../circom/inputs/jwt_rs256/default.json
```
