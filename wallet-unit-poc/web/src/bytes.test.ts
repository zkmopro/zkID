import { describe, expect, it } from "vitest";

import { base64ToBytes, bytesToHex, hexToBytes } from "./bytes";

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
