// Byte-array conversion helpers. Tight, shared across clients + pipeline.

/** Byte-for-byte parity with the native Rust prover: `challenge_bytes` is an
 *  opaque string. HiPKI signs it verbatim; the RS256 circuit consumes its
 *  UTF-8 bytes (identical to ASCII for hex chars). Do NOT hex-decode — the
 *  server can emit odd-length strings, and hex-decoding would diverge from
 *  the native prover even on even-length inputs. */
export function challengeBytesToTbs(challengeBytes: string): Uint8Array {
  return new TextEncoder().encode(challengeBytes);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: non-hex character at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
