import { describe, expect, it } from "vitest";

import {
  base64ToBytes,
  bytesToHex,
  challengeBytesToTbs,
  hexToBytes,
} from "./bytes";

describe("hexToBytes", () => {
  it("decodes plain hex", () => {
    expect(hexToBytes("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("strips 0x prefix", () => {
    expect(hexToBytes("0xdeadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    expect(hexToBytes("0Xdeadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("decodes empty string to empty array", () => {
    expect(hexToBytes("")).toEqual(new Uint8Array(0));
  });

  it("throws on odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow(/odd-length/);
  });

  it("throws on non-hex chars", () => {
    expect(() => hexToBytes("zzzz")).toThrow(/non-hex/);
  });
});

describe("bytesToHex", () => {
  it("encodes plain bytes", () => {
    expect(bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(
      "deadbeef",
    );
  });

  it("pads single-digit bytes", () => {
    expect(bytesToHex(new Uint8Array([0x0, 0x1, 0xa]))).toBe("00010a");
  });

  it("round-trips with hexToBytes", () => {
    const bytes = new Uint8Array([0, 1, 255, 127, 128]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });
});

describe("challengeBytesToTbs", () => {
  // Byte-for-byte parity with the native Rust prover's `.into_bytes()` on
  // the raw `challenge_bytes` string. If this diverges from UTF-8 encoding,
  // web-generated proofs stop verifying against the same challenge.
  it("encodes even-length hex string as ASCII bytes (matches Rust .into_bytes())", () => {
    // "deadbeef" → [0x64, 0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66]
    expect(challengeBytesToTbs("deadbeef")).toEqual(
      new Uint8Array([0x64, 0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66]),
    );
  });

  it("handles odd-length hex without throwing (regression: server may emit odd-length)", () => {
    // 31-char fixture. Hex-decoding this would throw; UTF-8 encoding must
    // succeed and produce 31 bytes.
    const out = challengeBytesToTbs("deadbeefcafebabe1234567890abcde");
    expect(out.byteLength).toBe(31);
    expect(out[0]).toBe(0x64);
    expect(out[out.length - 1]).toBe(0x65);
  });

  it("encodes empty string to empty array", () => {
    expect(challengeBytesToTbs("")).toEqual(new Uint8Array(0));
  });
});

describe("base64ToBytes", () => {
  it("round-trips simple bytes", () => {
    // base64 of "zkID" = "emtJRA=="
    expect(base64ToBytes("emtJRA==")).toEqual(
      new Uint8Array([0x7a, 0x6b, 0x49, 0x44]),
    );
  });

  it("handles empty input", () => {
    expect(base64ToBytes("")).toEqual(new Uint8Array(0));
  });
});
