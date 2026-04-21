import { describe, expect, it } from "vitest";

import {
  SNAPSHOT_HEADER_BYTES,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  iterateNodeChunks,
  parseSnapshotHeader,
} from "./smt-snapshot";

function writeHeader(opts: {
  nodeCount: number;
  rootHashHex: string; // 64 hex chars (no 0x); left-padded
  depth: number;
  crlNumber: bigint;
}): Uint8Array {
  const buf = new Uint8Array(SNAPSHOT_HEADER_BYTES);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, SNAPSHOT_MAGIC, false);
  dv.setUint16(2, SNAPSHOT_VERSION, false);
  dv.setUint32(4, opts.nodeCount, false);
  const hash = opts.rootHashHex.padStart(64, "0");
  for (let i = 0; i < 32; i++) {
    buf[8 + i] = parseInt(hash.slice(i * 2, i * 2 + 2), 16);
  }
  dv.setUint32(40, opts.depth, false);
  dv.setBigUint64(44, opts.crlNumber, false);
  return buf;
}

function branchNode(hashByte = 0xab, leftByte = 0x01, rightByte = 0x02): Uint8Array {
  const n = new Uint8Array(97);
  n[0] = 0; // branch
  n.fill(hashByte, 1, 33);
  n.fill(leftByte, 33, 65);
  n.fill(rightByte, 65, 97);
  return n;
}

function leafNode(
  hashByte = 0xcd,
  keyByte = 0x10,
  valByte = 0x11,
  markByte = 0x12,
): Uint8Array {
  const n = new Uint8Array(129);
  n[0] = 1; // leaf
  n.fill(hashByte, 1, 33);
  n.fill(keyByte, 33, 65);
  n.fill(valByte, 65, 97);
  n.fill(markByte, 97, 129);
  return n;
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

describe("parseSnapshotHeader", () => {
  it("reads magic/version/count/root/depth/crlNumber", () => {
    const header = writeHeader({
      nodeCount: 1234,
      rootHashHex: "00deadbeef",
      depth: 128,
      crlNumber: 2026042110n,
    });
    const parsed = parseSnapshotHeader(header);
    expect(parsed.magic).toBe(SNAPSHOT_MAGIC);
    expect(parsed.version).toBe(SNAPSHOT_VERSION);
    expect(parsed.nodeCount).toBe(1234);
    expect(parsed.rootHex).toBe("deadbeef");
    expect(parsed.depth).toBe(128);
    expect(parsed.crlNumber).toBe(2026042110n);
    expect(parsed.bodyOffset).toBe(SNAPSHOT_HEADER_BYTES);
  });

  it("emits rootHex = \"0\" for an all-zero root", () => {
    const header = writeHeader({
      nodeCount: 0,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    expect(parseSnapshotHeader(header).rootHex).toBe("0");
  });

  it("throws on bad magic", () => {
    const header = writeHeader({
      nodeCount: 0,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    header[0] = 0x12;
    header[1] = 0x34;
    expect(() => parseSnapshotHeader(header)).toThrow(/bad magic/);
  });

  it("throws on unsupported version", () => {
    const header = writeHeader({
      nodeCount: 0,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    header[2] = 0x00;
    header[3] = 0x09;
    expect(() => parseSnapshotHeader(header)).toThrow(/version/);
  });

  it("throws when input is shorter than header", () => {
    expect(() => parseSnapshotHeader(new Uint8Array(10))).toThrow(/too short/);
  });
});

describe("iterateNodeChunks", () => {
  it("yields node-aligned chunks and counts branches vs leaves", () => {
    const nodes = [branchNode(), leafNode(), branchNode(), leafNode(), leafNode()];
    const header = parseSnapshotHeader(
      writeHeader({
        nodeCount: nodes.length,
        rootHashHex: "ff",
        depth: 128,
        crlNumber: 1n,
      }),
    );
    const bytes = concat([
      writeHeader({
        nodeCount: nodes.length,
        rootHashHex: "ff",
        depth: 128,
        crlNumber: 1n,
      }),
      ...nodes,
    ]);

    const chunks = Array.from(iterateNodeChunks(bytes, header, 2));
    expect(chunks).toHaveLength(3);
    expect(chunks[0].nodes).toBe(2);
    expect(chunks[0].leaves).toBe(1);
    expect(chunks[0].slice.byteLength).toBe(97 + 129);
    expect(chunks[1].nodes).toBe(2);
    expect(chunks[1].leaves).toBe(1);
    expect(chunks[2].nodes).toBe(1);
    expect(chunks[2].leaves).toBe(1);

    // Slices point back into the source buffer at the correct offsets.
    expect(chunks[0].slice[0]).toBe(0); // first node is branch
    expect(chunks[0].slice[97]).toBe(1); // second node is leaf
  });

  it("handles a single-chunk walk", () => {
    const nodes = [branchNode(), leafNode()];
    const headerBytes = writeHeader({
      nodeCount: nodes.length,
      rootHashHex: "01",
      depth: 64,
      crlNumber: 42n,
    });
    const header = parseSnapshotHeader(headerBytes);
    const bytes = concat([headerBytes, ...nodes]);
    const chunks = Array.from(iterateNodeChunks(bytes, header, 1000));
    expect(chunks).toHaveLength(1);
    expect(chunks[0].nodes).toBe(2);
    expect(chunks[0].leaves).toBe(1);
  });

  it("throws on truncated node bytes", () => {
    const headerBytes = writeHeader({
      nodeCount: 1,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    const header = parseSnapshotHeader(headerBytes);
    // Body is only 10 bytes — far short of a full node.
    const truncated = concat([headerBytes, new Uint8Array(10)]);
    expect(() => Array.from(iterateNodeChunks(truncated, header, 64))).toThrow(
      /truncated/,
    );
  });

  it("throws on unknown node type", () => {
    const headerBytes = writeHeader({
      nodeCount: 1,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    const header = parseSnapshotHeader(headerBytes);
    const bad = new Uint8Array(97);
    bad[0] = 0xff;
    const bytes = concat([headerBytes, bad]);
    expect(() => Array.from(iterateNodeChunks(bytes, header, 64))).toThrow(
      /bad node type/,
    );
  });

  it("throws on trailing bytes after declared nodeCount", () => {
    const headerBytes = writeHeader({
      nodeCount: 1,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    const header = parseSnapshotHeader(headerBytes);
    const bytes = concat([headerBytes, branchNode(), new Uint8Array(5)]);
    expect(() => Array.from(iterateNodeChunks(bytes, header, 64))).toThrow(
      /trailing/,
    );
  });

  it("accumulates leaf counts across chunks", () => {
    const headerBytes = writeHeader({
      nodeCount: 5,
      rootHashHex: "",
      depth: 128,
      crlNumber: 0n,
    });
    const header = parseSnapshotHeader(headerBytes);
    const bytes = concat([
      headerBytes,
      branchNode(),
      leafNode(),
      branchNode(),
      leafNode(),
      leafNode(),
    ]);
    const totalLeaves = Array.from(iterateNodeChunks(bytes, header, 2)).reduce(
      (sum, c) => sum + c.leaves,
      0,
    );
    expect(totalLeaves).toBe(3);
  });
});
