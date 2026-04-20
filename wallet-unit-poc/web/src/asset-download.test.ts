// Tests for asset-download.ts. fake-indexeddb/auto installs a global
// `indexedDB` shim so asset-store.ts's IDB fallback is exercised — OPFS is
// unavailable in Node, so hasOPFS() returns false and we hit the IDB path.

import "fake-indexeddb/auto";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ensureAsset } from "./asset-download";
import { assetStore } from "./asset-store";

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

  beforeEach(async () => {
    // Reset fake IDB between tests by deleting the known keys.
    await assetStore.delete("cache-key-happy").catch(() => {});
    await assetStore.delete("cache-key-mismatch").catch(() => {});
    await assetStore.delete("cache-key-cached").catch(() => {});
    await assetStore.delete("cache-key-empty").catch(() => {});
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("downloads, decompresses, verifies hash, and caches bytes", async () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const expected = sha256HexOf(raw);
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    const progressUpdates: Array<{ bytesDone: number; bytesTotal: number }> = [];
    const out = await ensureAsset(testUrl, "cache-key-happy", expected, (p) =>
      progressUpdates.push({ ...p }),
    );

    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(progressUpdates.length).toBeGreaterThan(0);

    const cached = await assetStore.get("cache-key-happy");
    expect(cached).not.toBeNull();
    expect(Array.from(cached!)).toEqual(Array.from(raw));
  });

  it("throws and clears cache on hash mismatch", async () => {
    const raw = new Uint8Array([9, 8, 7, 6]);
    const wrongHash =
      "0000000000000000000000000000000000000000000000000000000000000000";
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-mismatch", wrongHash, () => {}),
    ).rejects.toThrow(/hash mismatch/);

    const cached = await assetStore.get("cache-key-mismatch");
    expect(cached).toBeNull();
  });

  it("returns cached bytes without fetching when hash matches", async () => {
    const raw = new Uint8Array([42, 42, 42, 42, 42]);
    const expected = sha256HexOf(raw);
    await assetStore.put("cache-key-cached", raw);

    const fetchSpy = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const out = await ensureAsset(testUrl, "cache-key-cached", expected, () => {});
    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("skips hash verification when expectedSha256 is empty", async () => {
    const raw = new Uint8Array([100, 101, 102]);
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    const out = await ensureAsset(testUrl, "cache-key-empty", "", () => {});
    expect(Array.from(out)).toEqual(Array.from(raw));

    const cached = await assetStore.get("cache-key-empty");
    expect(cached).not.toBeNull();
    expect(Array.from(cached!)).toEqual(Array.from(raw));
  });

  it("throws and leaves no cache entry on non-2xx response", async () => {
    await assetStore.delete("cache-key-500").catch(() => {});
    globalThis.fetch = vi.fn(async () =>
      new Response("oops", { status: 500, statusText: "Internal Server Error" }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-500", "", () => {}),
    ).rejects.toThrow(/500/);

    const cached = await assetStore.get("cache-key-500");
    expect(cached).toBeNull();
  });

  it("throws and clears cache on malformed gzip payload", async () => {
    await assetStore.delete("cache-key-badgz").catch(() => {});
    const junk = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    globalThis.fetch = vi.fn(async () =>
      new Response(junk.buffer as ArrayBuffer, {
        status: 200,
        headers: { "Content-Length": String(junk.byteLength) },
      }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-badgz", "", () => {}),
    ).rejects.toThrow();

    const cached = await assetStore.get("cache-key-badgz");
    expect(cached).toBeNull();
  });
});
