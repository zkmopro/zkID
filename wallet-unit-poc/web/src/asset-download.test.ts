import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ensureAsset } from "./asset-download";

function sha256HexOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function gzippedResponse(bytes: Uint8Array): Response {
  const gz = gzipSync(bytes);
  const ab = gz.buffer.slice(gz.byteOffset, gz.byteOffset + gz.byteLength);
  return new Response(ab as ArrayBuffer, {
    status: 200,
    headers: { "Content-Length": String(gz.byteLength) },
  });
}

describe("ensureAsset", () => {
  const originalFetch = globalThis.fetch;
  const testUrl = "/keys/test-asset.bin.gz";

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("downloads, decompresses, verifies hash, and returns bytes", async () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const expected = sha256HexOf(raw);
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    const progressUpdates: Array<{ bytesDone: number; bytesTotal: number }> = [];
    const out = await ensureAsset(testUrl, expected, (p) =>
      progressUpdates.push({ ...p }),
    );

    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(progressUpdates.length).toBeGreaterThan(0);
  });

  it("throws on hash mismatch", async () => {
    const raw = new Uint8Array([9, 8, 7, 6]);
    const wrongHash =
      "0000000000000000000000000000000000000000000000000000000000000000";
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    await expect(
      ensureAsset(testUrl, wrongHash, () => {}),
    ).rejects.toThrow(/hash mismatch/);
  });

  it("skips hash verification when expectedSha256 is empty", async () => {
    const raw = new Uint8Array([100, 101, 102]);
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    const out = await ensureAsset(testUrl, "", () => {});
    expect(Array.from(out)).toEqual(Array.from(raw));
  });

  it("throws on non-2xx response", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response("oops", { status: 500, statusText: "Internal Server Error" }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "", () => {}),
    ).rejects.toThrow(/500/);
  });

  it("throws on malformed gzip payload", async () => {
    const junk = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    globalThis.fetch = vi.fn(async () =>
      new Response(junk.buffer as ArrayBuffer, {
        status: 200,
        headers: { "Content-Length": String(junk.byteLength) },
      }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "", () => {}),
    ).rejects.toThrow();
  });
});
