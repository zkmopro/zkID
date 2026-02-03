#!/usr/bin/env python3
"""
RS256 JWT Test Data Generator for zkID Circuit Testing

Generates fake RS256-signed JWT test data for zero-knowledge circuit testing.
The output format is compatible with circom circuits that verify RSA signatures.

Usage:
    python generate_rsa_jwt.py --output ../test_data/rsa_jwt_test.json
    python generate_rsa_jwt.py --birthday "1040605"
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from ecdsa import NIST256p, SigningKey
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install cryptography ecdsa")
    sys.exit(1)


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding_needed = 4 - len(data) % 4
    if padding_needed != 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data)


def bigint_to_limbs(value: int, limb_bits: int = 121, num_limbs: int = 17) -> list[str]:
    """
    Convert BigInt to array of limbs for circom circuit.

    RSA 2048-bit values are split into 17 limbs of 121 bits each.
    17 * 121 = 2057 bits, which accommodates 2048 bits with room for carry.
    """
    limbs = []
    mask = (1 << limb_bits) - 1
    for _ in range(num_limbs):
        limbs.append(str(value & mask))
        value >>= limb_bits
    return limbs


def limbs_to_bigint(limbs: list[str], limb_bits: int = 121) -> int:
    """Convert limbs back to BigInt (for verification)."""
    value = 0
    for i, limb in enumerate(limbs):
        value += int(limb) << (i * limb_bits)
    return value


def generate_rsa_keypair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA key pair with standard public exponent 65537."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_device_keypair() -> tuple[SigningKey, dict]:
    """Generate P-256 (secp256r1) key pair for device binding."""
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.get_verifying_key()

    # Get x and y coordinates (32 bytes each)
    public_bytes = public_key.to_string()
    x_bytes = public_bytes[:32]
    y_bytes = public_bytes[32:]

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x_bytes),
        "y": base64url_encode(y_bytes)
    }

    return private_key, jwk


def create_jwt_header() -> dict:
    """Create JWT header for RS256."""
    return {
        "alg": "RS256",
        "typ": "vc+sd-jwt",
        "kid": "rsa-test-key-1"
    }


def create_jwt_payload(device_jwk: dict, claims: list[dict], hashed_claims: list[str]) -> dict:
    """Create JWT payload with device binding and selective disclosure."""
    now = int(time.time())
    nonce = base64url_encode(secrets.token_bytes(16))

    # Generate DID-like identifiers
    subject_did = f"did:key:z{base64url_encode(secrets.token_bytes(32))}"
    issuer_did = f"did:key:z{base64url_encode(secrets.token_bytes(32))}"

    return {
        "sub": subject_did,
        "iss": issuer_did,
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
        "nonce": nonce,
        "cnf": {
            "jwk": device_jwk
        },
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {
                "_sd": hashed_claims,
                "_sd_alg": "sha-256"
            }
        }
    }


def generate_claim(key: str, value: str) -> tuple[str, str]:
    """
    Generate SD-JWT claim with salt.
    Returns (encoded_claim, hash_of_claim).
    """
    salt = base64url_encode(secrets.token_bytes(16))
    claim_array = [salt, key, value]
    claim_json = json.dumps(claim_array, separators=(',', ':'))
    encoded = base64url_encode(claim_json.encode('utf-8'))

    # Hash the encoded claim (as per SD-JWT spec)
    claim_hash = hashlib.sha256(encoded.encode('utf-8')).digest()
    hashed = base64url_encode(claim_hash)

    return encoded, hashed


def sign_rs256(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign message with RS256 (RSASSA-PKCS1-v1_5 with SHA-256)."""
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify_rs256(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify RS256 signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def generate_rsa_jwt_test_data(birthday: str = "1040605") -> dict[str, Any]:
    """
    Generate complete RS256 JWT test data for circuit testing.

    Args:
        birthday: ROC birthday in YYYMMDD format (e.g., "1040605" = 2015-06-05)

    Returns:
        Dictionary containing JWT, RSA public key, signature, device key, and claims
        in circuit-compatible format.
    """
    # Generate RSA key pair
    rsa_private, rsa_public = generate_rsa_keypair(2048)

    # Extract RSA modulus
    public_numbers = rsa_public.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    # Generate device binding key (P-256)
    device_private, device_jwk = generate_device_keypair()
    device_private_hex = device_private.to_string().hex()

    # Generate claims
    claims_data = [
        {"key": "name", "value": "Test User"},
        {"key": "roc_birthday", "value": birthday}
    ]

    claims = []
    hashed_claims = []
    for claim_data in claims_data:
        encoded, hashed = generate_claim(claim_data["key"], claim_data["value"])
        claims.append({
            "key": claim_data["key"],
            "value": claim_data["value"],
            "encoded": encoded,
            "hash": hashed
        })
        hashed_claims.append(hashed)

    # Create JWT parts
    header = create_jwt_header()
    payload = create_jwt_payload(device_jwk, claims_data, hashed_claims)

    # Encode header and payload
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))

    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}"
    message_bytes = signing_input.encode('ascii')

    # Sign with RS256
    signature = sign_rs256(message_bytes, rsa_private)
    signature_b64 = base64url_encode(signature)

    # Create full JWT
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"

    # Verify signature
    if not verify_rs256(message_bytes, signature, rsa_public):
        raise ValueError("Signature verification failed!")

    # Convert RSA values to limbs
    n_limbs = bigint_to_limbs(n)
    sig_int = int.from_bytes(signature, 'big')
    sig_limbs = bigint_to_limbs(sig_int)

    # Verify limb conversion is reversible
    n_recovered = limbs_to_bigint(n_limbs)
    sig_recovered = limbs_to_bigint(sig_limbs)

    if n_recovered != n:
        raise ValueError("Modulus limb conversion is not reversible!")
    if sig_recovered != sig_int:
        raise ValueError("Signature limb conversion is not reversible!")

    # Export RSA public key in PEM format
    rsa_pem = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Build output
    result = {
        "jwt": {
            "token": jwt_token,
            "header": header_b64,
            "payload": payload_b64,
            "signature": signature_b64
        },
        "rsaPublicKey": {
            "n": format(n, 'x'),  # Hex string
            "e": e,
            "nLimbs": n_limbs,
            "pem": rsa_pem
        },
        "signatureLimbs": sig_limbs,
        "signatureHex": signature.hex(),
        "deviceKey": {
            "privateKeyHex": device_private_hex,
            "publicKey": device_jwk
        },
        "claims": claims,
        "hashedClaims": hashed_claims,
        "message": {
            "raw": signing_input,
            "bytes": list(message_bytes),
            "length": len(message_bytes)
        },
        "metadata": {
            "rsaBits": 2048,
            "rsaLimbs": 17,
            "limbBits": 121,
            "algorithm": "RS256",
            "generated_at": int(time.time())
        }
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate RS256 JWT test data for zkID circuit testing"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (default: print to stdout)"
    )
    parser.add_argument(
        "--birthday", "-b",
        type=str,
        default="1040605",
        help="ROC birthday in YYYMMDD format (default: 1040605)"
    )
    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty print JSON output"
    )

    args = parser.parse_args()

    # Generate test data
    test_data = generate_rsa_jwt_test_data(birthday=args.birthday)

    # Format output
    indent = 2 if args.pretty else None
    json_output = json.dumps(test_data, indent=indent)

    # Write or print
    if args.output:
        output_path = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(json_output)
        print(f"Generated RS256 JWT test data: {output_path}")
        print(f"  RSA modulus bits: 2048")
        print(f"  RSA limbs: 17 x 121 bits")
        print(f"  JWT length: {len(test_data['jwt']['token'])} chars")
        print(f"  Message length: {test_data['message']['length']} bytes")
        print(f"  Claims: {len(test_data['claims'])}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
