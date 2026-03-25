# ecdsa-spartan2

Spartan2-based proving tooling for the zkID wallet proof of concept.

Provides CLI subcommands for:
- **RS256 certificate chain verification** — generates circuit inputs from Taiwan Citizen Digital Certificate (自然人憑證) via HiPKI LocalSignServer, then runs setup/prove/verify
- **JWT-RS256 single-stage circuit** — setup, prove, and verify against Circom inputs

## RS256 Certificate Chain Flow

### Prerequisites

- **Default mode**: No prerequisites (uses bundled test fixtures)
- **Live mode**: [HiPKI LocalSignServer](https://publicca.hinet.net/HiPKI-01.htm) running on `localhost:61161`, a card reader, and a valid Citizen Digital Certificate

### 1. Generate circuit input

```sh
# Default mode — uses bundled test data (no card reader needed)
RUST_LOG=info cargo run --release -- rs256 generate-input

# Live mode — calls HiPKI APIs directly (requires card + reader + HiPKI server)
RUST_LOG=info cargo run --release -- rs256 generate-input --tbs 123456 --pin <YOUR_PIN>

# Live mode with SMT revocation checking
RUST_LOG=info cargo run --release -- rs256 generate-input \
  --tbs 123456 --pin <YOUR_PIN> --smt-server http://localhost:3000
```

In live mode, the CLI:
1. Calls `GET /pkcs11info?withcert=true` to fetch the certificate chain (Root CA, MOICA CA, user certs)
2. Calls `POST /sign` with the TBS data and PIN to get a raw PKCS#1 v1.5 RSA signature
3. Extracts the issuer (CA) certificate, verifies the chain, and generates the 18-field circuit input JSON

### 2. Setup, prove, verify

```sh
# Compile the circom circuit first (if not already done)
cd ../circom && yarn compile:rs256 && cd ../ecdsa-spartan2

# Generate proving/verifying keys
RUST_LOG=info cargo run --release -- rs256 setup --input ../circom/inputs/rs256/input.json

# Generate proof
RUST_LOG=info cargo run --release -- rs256 prove --input ../circom/inputs/rs256/input.json

# Verify proof
RUST_LOG=info cargo run --release -- rs256 verify
```

### 3. Benchmark

```sh
RUST_LOG=info cargo run --release -- rs256 benchmark --input ../circom/inputs/rs256/input.json
```

## JWT-RS256 Flow

```sh
# Setup
RUST_LOG=info cargo run --release -- jwt_rs256 setup --input ../circom/inputs/jwt_rs256/default.json

# Prove
RUST_LOG=info cargo run --release -- jwt_rs256 prove --input ../circom/inputs/jwt_rs256/default.json

# Verify
RUST_LOG=info cargo run --release -- jwt_rs256 verify

# Benchmark
RUST_LOG=info cargo run --release -- jwt_rs256 benchmark --input ../circom/inputs/jwt_rs256/default.json
```

## Tests

```sh
cargo test --release
```
