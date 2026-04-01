# zkID Web Demo

Browser-based RS256 certificate proof pipeline using Spartan2.

## Architecture

```
Browser                          Prove Server              go-zkid-verifier
┌─────────────────┐              ┌──────────────────┐     ┌──────────────┐
│ 1. Load cert    │              │                  │     │              │
│ 2. Generate     │──input───▶   │ 3. Witness +     │     │              │
│    (prepare     │   (POST)     │    Prove         │     │              │
│     input)      │              │    (Spartan2)    │     │              │
│                 │◀──proof───   │                  │     │              │
│ 4. Send proof   │──proof──────────────────────────────▶ │ 5. Verify    │
│ 5. Show result  │◀────────────────────────────result──  │              │
└─────────────────┘              └──────────────────┘     └──────────────┘
```

**Hybrid approach:** The browser loads certificate data and prepares circuit inputs.
The proving server generates the Spartan2 proof (requires 744MB proving key + native Rust).
The go-zkid-verifier performs off-chain verification.

## WASM Spike Results

Spartan2 compiles to WASM successfully (299KB binary). Rayon has a built-in
sequential fallback for `wasm32-unknown-unknown` — no fork needed. Client-side
verification is feasible for future work. Client-side proving requires further
investigation (744MB PK + 636MB R1CS + 128MB witness = 1.5GB+ static data).

## Setup

```bash
# Install dependencies
pnpm install

# Copy circuit assets from circom build
bash scripts/copy-assets.sh

# Build the WASM module (optional, for client-side verification)
cd wasm && wasm-pack build --target web --release && cd ..

# Run dev server
pnpm dev
```

## Prerequisites

- Circom RS256 circuit compiled: `cd ../circom && npx circomkit compile rs256`
- Proving server running: `cd ../ecdsa-spartan2 && cargo run -- rs256 serve`
- go-zkid-verifier running: see https://github.com/zkmopro/go-zkid-verifier

## Circuit Artifacts

| Artifact | Size | Location |
|----------|------|----------|
| Proving key | 744MB | `../ecdsa-spartan2/keys/rs256_proving.key` |
| Verifying key | 744MB | `../ecdsa-spartan2/keys/rs256_verifying.key` |
| R1CS | 636MB | `../circom/build/rs256/rs256_js/rs256.r1cs` |
| Witness WASM | 11MB | `../circom/build/rs256/rs256_js/rs256.wasm` |
| Proof output | ~176KB | Generated per-proof |
| Test input | 46KB | `public/assets/rs256-input.json` |
