import { strict as assert } from "assert";
import { sha256Pad } from "@zk-email/helpers";
import { sha256 } from "@noble/hashes/sha2";
import { base64urlToBase64, encodeClaims, stringToPaddedBigIntArray, bigintToLimbs } from "./utils.ts";
import * as crypto from "crypto";

// RS256 JWT Circuit Parameters
export interface JWTRS256CircuitParams {
  maxMessageLength: number;      // 1920
  maxB64PayloadLength: number;   // 1900
  maxMatches: number;            // 4
  maxSubstringLength: number;    // 50
  maxClaimsLength: number;       // 128
  n: number;                     // 121 (RSA limb bits)
  k: number;                     // 17 (RSA limbs for 2048-bit)
}

// RSA Public Key in JWK format
export interface JwkRsaPublicKey {
  kty: string;
  n: string;   // modulus (base64url)
  e: string;   // exponent (base64url)
  kid?: string;
}

// RSA Public Key in PEM format
export interface PemRsaPublicKey {
  pem: string;
}

// Generate RS256 JWT Circuit Parameters from array
export function generateJWTRS256CircuitParams(params: number[]): JWTRS256CircuitParams {
  return {
    maxMessageLength: params[0],
    maxB64PayloadLength: params[1],
    maxMatches: params[2],
    maxSubstringLength: params[3],
    maxClaimsLength: params[4],
    n: params[5],
    k: params[6],
  };
}

// Convert base64url string to BigInt
function base64urlToBigInt(b64url: string): bigint {
  const b64 = base64urlToBase64(b64url);
  const buffer = Buffer.from(b64, "base64");
  const hex = buffer.toString("hex");
  return BigInt("0x" + hex);
}

// Extract RSA modulus from PEM public key
function extractRsaModulusFromPEM(pem: string): bigint {
  // Remove PEM headers and newlines
  const pemBody = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
    .replace("-----END RSA PUBLIC KEY-----", "")
    .replaceAll("\n", "")
    .replaceAll("\r", "");

  // Decode base64
  const der = Buffer.from(pemBody, "base64");

  // Parse ASN.1 DER structure to extract modulus
  // For PKCS#8 SubjectPublicKeyInfo:
  // SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER (n), INTEGER (e) } } }
  // For PKCS#1 RSAPublicKey:
  // SEQUENCE { INTEGER (n), INTEGER (e) }

  let offset = 0;

  // Helper to read ASN.1 length
  const readLength = (buf: Buffer, pos: number): [number, number] => {
    const firstByte = buf[pos];
    if (firstByte < 0x80) {
      return [firstByte, 1];
    }
    const numBytes = firstByte & 0x7f;
    let length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[pos + 1 + i];
    }
    return [length, 1 + numBytes];
  };

  // Read outer SEQUENCE
  if (der[offset] !== 0x30) throw new Error("Expected SEQUENCE");
  offset++;
  const [, outerLenBytes] = readLength(der, offset);
  offset += outerLenBytes;

  // Check if this is PKCS#8 (starts with SEQUENCE containing OID) or PKCS#1 (starts with INTEGER)
  if (der[offset] === 0x30) {
    // PKCS#8 format - skip algorithm identifier sequence
    offset++;
    const [algIdLen, algIdLenBytes] = readLength(der, offset);
    offset += algIdLenBytes + algIdLen;

    // Read BIT STRING
    if (der[offset] !== 0x03) throw new Error("Expected BIT STRING");
    offset++;
    const [, bitStringLenBytes] = readLength(der, offset);
    offset += bitStringLenBytes;
    offset++; // Skip unused bits count

    // Read inner SEQUENCE (RSAPublicKey)
    if (der[offset] !== 0x30) throw new Error("Expected inner SEQUENCE");
    offset++;
    const [, innerSeqLenBytes] = readLength(der, offset);
    offset += innerSeqLenBytes;
  }

  // Now we should be at the INTEGER (modulus)
  if (der[offset] !== 0x02) throw new Error("Expected INTEGER for modulus");
  offset++;
  const [modulusLen, modulusLenBytes] = readLength(der, offset);
  offset += modulusLenBytes;

  // Read modulus bytes (skip leading zero if present)
  let modulusStart = offset;
  let modulusLength = modulusLen;
  if (der[modulusStart] === 0x00) {
    modulusStart++;
    modulusLength--;
  }

  const modulusBytes = der.subarray(modulusStart, modulusStart + modulusLength);
  return BigInt("0x" + modulusBytes.toString("hex"));
}

// Verify RS256 signature using Node.js crypto
function verifyRS256Signature(
  message: string,
  signatureB64url: string,
  publicKeyPem: string
): boolean {
  const signature = Buffer.from(base64urlToBase64(signatureB64url), "base64");
  const verify = crypto.createVerify("RSA-SHA256");
  verify.update(message);
  return verify.verify(publicKeyPem, signature);
}

// Convert JWK to PEM format for verification
function jwkToPem(jwk: JwkRsaPublicKey): string {
  // This is a simplified conversion - for production, use a proper library
  const n = Buffer.from(base64urlToBase64(jwk.n), "base64");
  const e = Buffer.from(base64urlToBase64(jwk.e), "base64");

  // Build RSAPublicKey ASN.1 structure
  const encodeInteger = (buf: Buffer): Buffer => {
    // Add leading zero if high bit is set
    const needsLeadingZero = buf[0] & 0x80;
    const intBuf = needsLeadingZero ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
    return Buffer.concat([
      Buffer.from([0x02]), // INTEGER tag
      encodeLength(intBuf.length),
      intBuf,
    ]);
  };

  const encodeLength = (len: number): Buffer => {
    if (len < 0x80) {
      return Buffer.from([len]);
    } else if (len < 0x100) {
      return Buffer.from([0x81, len]);
    } else if (len < 0x10000) {
      return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    }
    throw new Error("Length too long");
  };

  const nEncoded = encodeInteger(n);
  const eEncoded = encodeInteger(e);
  const rsaPublicKey = Buffer.concat([
    Buffer.from([0x30]), // SEQUENCE
    encodeLength(nEncoded.length + eEncoded.length),
    nEncoded,
    eEncoded,
  ]);

  // Wrap in SubjectPublicKeyInfo
  const algorithmIdentifier = Buffer.from([
    0x30, 0x0d, // SEQUENCE (13 bytes)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
    0x05, 0x00, // NULL
  ]);

  const bitString = Buffer.concat([
    Buffer.from([0x03]), // BIT STRING
    encodeLength(rsaPublicKey.length + 1),
    Buffer.from([0x00]), // unused bits
    rsaPublicKey,
  ]);

  const subjectPublicKeyInfo = Buffer.concat([
    Buffer.from([0x30]), // SEQUENCE
    encodeLength(algorithmIdentifier.length + bitString.length),
    algorithmIdentifier,
    bitString,
  ]);

  const pem =
    "-----BEGIN PUBLIC KEY-----\n" +
    subjectPublicKeyInfo.toString("base64").match(/.{1,64}/g)!.join("\n") +
    "\n-----END PUBLIC KEY-----";

  return pem;
}

// Generate RS256 JWT circuit inputs
export function generateJWTRS256Inputs(
  params: JWTRS256CircuitParams,
  token: string,
  pk: JwkRsaPublicKey | PemRsaPublicKey,
  matches: string[],
  claims: string[],
  decodeFlags: number[],
  currentDate: { year: number; month: number; day: number }
) {
  // Split JWT token
  const [b64header, b64payload, b64signature] = token.split(".");

  // Check limits
  assert.ok(b64payload.length <= params.maxB64PayloadLength, "Payload too long");
  assert.ok(matches.length <= params.maxMatches, "Too many matches");

  // Get message (header.payload)
  const message = `${b64header}.${b64payload}`;
  assert.ok(message.length <= params.maxMessageLength, "Message too long");

  // Extract RSA modulus
  let rsaModulusBigInt: bigint;
  let pemKey: string;

  if ("pem" in pk) {
    pemKey = pk.pem;
    rsaModulusBigInt = extractRsaModulusFromPEM(pk.pem);
  } else {
    assert.ok(pk.kty === "RSA", "Expected RSA key type");
    rsaModulusBigInt = base64urlToBigInt(pk.n);
    pemKey = jwkToPem(pk);
  }

  // Verify signature
  const isValid = verifyRS256Signature(message, b64signature, pemKey);
  assert.ok(isValid, "RS256 signature verification failed");

  // Convert modulus to limbs
  const rsaModulus = bigintToLimbs(rsaModulusBigInt, params.n, params.k);

  // Convert signature to limbs
  const signatureBytes = Buffer.from(base64urlToBase64(b64signature), "base64");
  const signatureBigInt = BigInt("0x" + signatureBytes.toString("hex"));
  const rsaSignature = bigintToLimbs(signatureBigInt, params.n, params.k);

  // Generate padded message
  const encoder = new TextEncoder();
  const messageUint8Array = encoder.encode(message);
  const [messagePadded, messagePaddedLen] = sha256Pad(messageUint8Array, params.maxMessageLength);

  // Decode payload for pattern matching
  const payload = Buffer.from(base64urlToBase64(b64payload), "base64").toString("utf8");

  // Build match arrays
  let matchSubstring: bigint[][] = [];
  let matchLength: number[] = [];
  let matchIndex: number[] = [];

  for (const pattern of matches) {
    assert.ok(pattern.length <= params.maxSubstringLength, `Pattern "${pattern}" too long`);
    const index = payload.indexOf(pattern);
    assert.ok(index !== -1, `Pattern "${pattern}" not found in payload`);
    matchSubstring.push(stringToPaddedBigIntArray(pattern, params.maxSubstringLength));
    matchLength.push(pattern.length);
    matchIndex.push(index);
  }

  // Pad to maxMatches
  while (matchSubstring.length < params.maxMatches) {
    matchSubstring.push(stringToPaddedBigIntArray("", params.maxSubstringLength));
    matchLength.push(0);
    matchIndex.push(0);
  }

  // Encode claims
  const { claimArray, claimLengths } = encodeClaims(claims, params.maxMatches, params.maxClaimsLength);

  // Pad decode flags
  const decodeFlagsPadded = [...decodeFlags];
  while (decodeFlagsPadded.length < params.maxMatches) {
    decodeFlagsPadded.push(0);
  }

  // Find age claim index
  const ageClaimOffset = claims.findIndex((claim) => {
    try {
      const decoded = Buffer.from(base64urlToBase64(claim), "base64").toString("utf8");
      const parsed = JSON.parse(decoded);
      return Array.isArray(parsed) && parsed[1] === "roc_birthday";
    } catch {
      return false;
    }
  });

  assert.ok(ageClaimOffset >= 0, "roc_birthday claim not found among provided claims");

  // Convert message to BigInt array
  const messageArray: bigint[] = [];
  for (const b of messagePadded) {
    messageArray.push(BigInt(b));
  }

  return {
    message: messageArray,
    messageLength: messagePaddedLen,
    periodIndex: message.indexOf("."),
    rsaModulus,
    rsaSignature,
    matchesCount: matches.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    decodeFlags: decodeFlagsPadded.slice(0, params.maxMatches),
    ageClaimIndex: ageClaimOffset,
    currentYear: currentDate.year,
    currentMonth: currentDate.month,
    currentDay: currentDate.day,
  };
}

// Hash a claim for SD-JWT verification
export function hashClaim(claim: string): string {
  const claimBuffer = Buffer.from(claim, "utf8");
  return Buffer.from(sha256(claimBuffer)).toString("base64url");
}
