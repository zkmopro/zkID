# ecdsa-spartan2

Spartan2-based proving tooling for the zkID wallet proof of concept.

Provides CLI subcommands for:
- **RS256 certificate chain verification** — generates circuit inputs from Taiwan Citizen Digital Certificate (自然人憑證) via HiPKI LocalSignServer, then runs setup/prove/verify

## RS256 Certificate Chain Flow

### Prerequisites

- **Default mode**: No prerequisites (uses bundled test fixtures)
- **Live mode**: [HiPKI LocalSignServer](https://publicca.hinet.net/HiPKI-01.htm) running on `localhost:61161`, a card reader, and a valid Citizen Digital Certificate

Two RSA key-size variants are supported, selected at build time via Cargo features:

| Feature flag      | Key size | CA         | Mode          |
|-------------------|----------|------------|---------------|
| `sha256rsa2048`   | RSA-2048 | MOICA-G2   | Default/HiPKI |
| `sha256rsa4096`   | RSA-4096 | MOICA-G3   | FIDO          |

### 1. Generate circuit input

#### RSA-2048 (MOICA-G2, default)

```sh
# Default mode — uses bundled test data (no card reader needed)
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 generate-input

# Live mode — calls HiPKI APIs directly (requires card + reader + HiPKI server)
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 generate-input --tbs 123456 --pin <YOUR_PIN>

# Live mode with SMT revocation checking
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 generate-input \
  --tbs 123456 --pin <YOUR_PIN> --smt-server http://localhost:3000
```

#### RSA-4096 (MOICA-G3, FIDO)

```sh
# Default mode — uses bundled FIDO test fixtures (no card reader needed)
RUST_LOG=info cargo run --release --features sha256rsa4096 -- rs256 generate-input --fido
```

In live mode, the CLI:
1. Calls `GET /pkcs11info?withcert=true` to fetch the certificate chain (Root CA, MOICA CA, user certs)
2. Calls `POST /sign` with the TBS data and PIN to get a raw PKCS#1 v1.5 RSA signature
3. Extracts the issuer (CA) certificate, verifies the chain, and generates the circuit input JSON

The output directory (`../circom/inputs/sha256rsa2048/` or `../circom/inputs/sha256rsa4096/`) is created automatically if it does not exist.

### 2. Setup, prove, verify

```sh
# Compile the circom circuits first (if not already done)
cd ../circom && yarn compile:all && cd ../ecdsa-spartan2
```

#### RSA-2048

```sh
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 setup --input ../circom/inputs/sha256rsa2048/input.json
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 prove --input ../circom/inputs/sha256rsa2048/input.json
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 verify
```

#### RSA-4096 (FIDO)

```sh
RUST_LOG=info cargo run --release --features sha256rsa4096 -- rs256 setup --fido --input ../circom/inputs/sha256rsa4096/input.json
RUST_LOG=info cargo run --release --features sha256rsa4096 -- rs256 prove --fido --input ../circom/inputs/sha256rsa4096/input.json
RUST_LOG=info cargo run --release --features sha256rsa4096 -- rs256 verify --fido
```

### 3. Benchmark

```sh
# RSA-2048
RUST_LOG=info cargo run --release --features sha256rsa2048 -- rs256 benchmark --input ../circom/inputs/sha256rsa2048/input.json

# RSA-4096 (FIDO)
RUST_LOG=info cargo run --release --features sha256rsa4096 -- rs256 benchmark --fido --input ../circom/inputs/sha256rsa4096/input.json
```

## Tests

```sh
cargo test --release
```
