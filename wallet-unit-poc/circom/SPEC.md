# zkID Circuit Specification

This document describes the Circom circuits in this directory.

## Overview

The circuits verify Taiwan Citizen Digital Certificate (MOICA) X.509
certificates signed with RSA-SHA256, plus a per-session user-device signature
over arbitrary data (the "TBS" sent to the HiPKI card). They also assert
non-revocation against a Sparse Merkle Tree (SMT).

## Active circuits

| Circuit         | Template                                | Description                                  |
| --------------- | --------------------------------------- | -------------------------------------------- |
| `sha256rsa2048` | `FullCertRSA256VerifyWithRevocation`    | RSA-2048 cert chain (MOICA-G2)               |
| `sha256rsa4096` | `FullCertRSA256VerifyWithRevocation`    | RSA-4096 cert chain (MOICA-G3 / FIDO)        |

Both share the same template with different `(n, k)` parameters for RSA limb
size and count. See `circuits/main/sha256rsa{2048,4096}.circom` for entry
points and `circuits/rs256.circom` for the template definition.

## What the circuit proves

For both variants, the circuit currently performs **two independent
RSA-SHA256 verifications** in one proof:

1. **Cert chain verify** — `issuer_rsa_modulus` (MOICA) verifies
   `issuer_rsa_signature` over `issuer_tbs` (the TBS portion of the user's
   cert). Proves that MOICA certified the user's public key.
2. **Device signature verify** — `user_rsa_extracted_modulus` (the user's pk
   pulled out of their cert via `ExtractModulus`) verifies
   `user_rsa_signature` over `tbs` (arbitrary bytes the HiPKI card signs via
   `/sign`). Proves that the holder of the user's private key signed `tbs`.

Plus:
- `VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber` — DER-level
  parsing checks that the user cert contains the claimed TBS, subject DN, and
  serial number at the prover-supplied offsets.
- `SMTNonMembershipVerifier` — proves `serialNumber` is **not** in the
  revocation tree rooted at `smtRoot`.
- `PoseidonBytes(subject_dn) → subject_dn_hash` — public-output commitment to
  the subject DN (private bytes; only the hash is revealed).
- `PackBytes(tbs) → packed_tbs` — public-output commitment to what the user
  signed.

## Public inputs / outputs

| Signal              | Visibility | Notes                                             |
| ------------------- | ---------- | ------------------------------------------------- |
| `issuer_rsa_modulus[k]` | public input  | MOICA's RSA public key (trust anchor)         |
| `smtRoot`           | public input  | Revocation SMT root                            |
| `serialNumber`      | public input  | Cert serial; planned to become private once the [`moica-revocation-smt`](https://github.com/moven0831/moica-revocation-smt) client-side WASM SMT lands |
| `subject_dn_hash`   | public output | `Poseidon(packed subject_dn)`                  |
| `packed_tbs`        | public output | `PackBytes(31, …)(tbs)` — commitment to the user-signed bytes |

All other signals (user cert bytes, both RSA signatures, SMT proof path,
`subject_dn`, `tbs`) are private.

## Revocation

Revocation uses a Sparse Merkle Tree non-membership proof against the SMT
maintained by the
[`moica-revocation-smt`](https://github.com/moven0831/moica-revocation-smt)
service. The circuit verifies that the cert's `serialNumber` is not present in
the tree rooted at `smtRoot`.

## See also

- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI
- `circuits/components/smt-nonmembership.circom` — SMT verification template
- `circuits/components/poseidon_p256.circom` — Poseidon hash over secq256r1
- `circuits/utils/utils.circom` — cert parsing helpers (`VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`)
