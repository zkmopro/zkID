# zkID Circuits

Circom circuits for X.509 RSA-SHA256 certificate chain verification with
revocation, used by the [zkID wallet PoC](../).

Compiled with [circomkit](https://github.com/erhant/circomkit) on the
secq256r1 prime field; proven by the Rust prover in
[`../ecdsa-spartan2`](../ecdsa-spartan2).

## Compile

```sh
yarn install

# Compile a single circuit
yarn compile:cert_chain_rs2048
yarn compile:cert_chain_rs4096
yarn compile:device_sig_rs2048

# Compile all
yarn compile:all
```

Use `yarn compile:all` rather than calling `npx circomkit compile` directly —
the script handles R1CS placement and copies the C++ witness calculator to
`build/cpp/`.

## Test

```sh
yarn test
```

Tests use `circom_tester` and run under mocha. The script sets
`NODE_OPTIONS=--max-old-space-size=16384` because the RS256 circuits are
memory-heavy.

## Layout

- `circuits/main/` — top-level circuit entry points (one file per build target)
- `circuits/rs256.circom` — RS256 cert verification and shared templates
- `circuits/cert_chain.circom` — CertChain circuit (Circuit A: cert chain + revocation + pk_commit)
- `circuits/device_sig.circom` — DeviceSig circuit (Circuit B: device signature + pk_commit)
- `circuits/components/` — reusable templates: SMT non-membership, Poseidon over P256
- `circuits/utils/utils.circom` — DER-level cert helpers (TBS / subject / serial extraction, modulus extraction, byte packing, Poseidon-over-bytes)

## See also

- [SPEC.md](./SPEC.md) — circuit specification (inputs, outputs, what's proven)
- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI usage
