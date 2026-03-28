# Circom validation of JWT ES256 tokens
## Resources

- **PoC Documentation:** [JWT Docs (Notion)](https://www.notion.so/pse-team/Seediq-JWT-Docs-1f1d57e8dd7e80018655ccdc7332b1af)
- **Circuit Specifications:** [SPEC.md](./SPEC.md)
- **Demo Video:** [Loom Walkthrough](https://www.loom.com/share/83cebc44d54a47baae959a643475e9e2?sid=e7ec15c4-1ab6-4334-9830-c341d2d76e41)
- **Live Frontend:** [https://privacy-scaling-explorations.github.io/seediq-frontend/](https://privacy-scaling-explorations.github.io/seediq-frontend/)


## Repositories

- **Frontend Repository:** [seediq-frontend](https://github.com/privacy-scaling-explorations/seediq-frontend)
- **Circuits Repository:** [zkID (Circuits)](https://github.com/privacy-scaling-explorations/zkID)

note: This project uses [circomkit](https://github.com/erhant/circomkit) to compile, setup, prove, and verify Circom circuits

```

## Circuits

- `es256` -- ECDSA signature verification (ES256)
- `jwt` -- JWT validation circuit
- `rs256` -- X.509 certificate RSA-SHA256 verification with revocation checking

### Components

- **DERSerialExtractor(maxLen, maxSerialLen)** -- Extracts a certificate serial number from a DER-encoded INTEGER field. Validates the 0x02 tag, reads `serialLength` bytes starting at `serialOffset + 2`, and packs them big-endian into a single field element.
- **ExtractSubjectDN(maxLen, maxDNLen)** -- Extracts the Subject Distinguished Name from a DER-encoded SEQUENCE. Validates the 0x30 tag and extracts up to `maxDNLen` bytes.
- **SMTNonMembershipVerifier(depth)** -- Verifies non-membership in a Sparse Merkle Tree for certificate revocation checking.

### Public Signals (rs256 main circuit)

- `issuer_rsa_modulus` -- Issuer RSA public key (input)
- `smtRoot` -- Sparse Merkle Tree root for revocation (input)
- `tbs_hash[256]` -- SHA-256 hash bits of the user's TBS certificate (output)
- `dn_nullifier` -- Poseidon hash of the Subject DN for unlinkable identity binding (output)

### Nullifier Computation

The DN nullifier provides a deterministic, unlinkable identifier derived from the Subject Distinguished Name:

1. Extract up to 256 DN bytes from the TBS certificate
2. Pack into 9 field elements (31 bytes each, big-endian)
3. Sequential Poseidon chain: `h = Poseidon(chunk[0], chunk[1])`, then `h = Poseidon(h, chunk[i])` for i=2..8
4. Output the final hash as `dn_nullifier`

## Testing

You can test the circuits in two main ways:

### 1. Using circom_tester via typescript

```
yarn test
```

### 2. Using circomkit CLI

The project includes build scripts for each circuit:

```
bash scripts/build jwt # Runs full flow for jwt.circom
bash scripts/build all # Runs all circuits
```

These commands automatically compile the circuit, download ptau according circuit size,run the proving ceremony, generate proofs using the inputs from default.json, and verify the proofs in a single workflow.
