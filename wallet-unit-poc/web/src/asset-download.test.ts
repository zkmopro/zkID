// Tests for asset-download.ts. fake-indexeddb/auto installs a global
// `indexedDB` shim so asset-store.ts's IDB fallback is exercised — OPFS is
// unavailable in Node, so hasOPFS() returns false and we hit the IDB path.

import "fake-indexeddb/auto";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ensureAsset } from "./asset-download";
import { assetStore } from "./asset-store";
import type { AuthorizingManifest } from "./manifest";

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

const AUTH: AuthorizingManifest = {
  manifestSha256: "a".repeat(64),
  fetchedAt: 1_700_000_000_000,
};

const AUTH_V2: AuthorizingManifest = {
  manifestSha256: "b".repeat(64),
  fetchedAt: 1_700_000_100_000,
};

describe("ensureAsset", () => {
  const originalFetch = globalThis.fetch;
  const testUrl = "/keys/test-asset.bin.gz";

  beforeEach(async () => {
    // Reset fake IDB between tests by deleting the known keys.
    for (const k of [
      "cache-key-happy",
      "cache-key-mismatch",
      "cache-key-cached",
      "cache-key-empty",
      "cache-key-500",
      "cache-key-badgz",
      "cache-key-stale",
      "cache-key-stale-bad",
      "cache-key-identity",
    ]) {
      await assetStore.delete(k).catch(() => {});
    }
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
    const out = await ensureAsset(
      testUrl,
      "cache-key-happy",
      expected,
      (p) => progressUpdates.push({ ...p }),
      AUTH,
    );

    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(progressUpdates.length).toBeGreaterThan(0);

    const cached = await assetStore.get("cache-key-happy");
    expect(cached).not.toBeNull();
    expect(Array.from(cached!)).toEqual(Array.from(raw));

    const meta = await assetStore.getMeta("cache-key-happy");
    expect(meta?.sha256).toBe(expected);
    expect(meta?.manifestSha256).toBe(AUTH.manifestSha256);
    expect(meta?.manifestFetchedAt).toBe(AUTH.fetchedAt);
    expect(typeof meta?.authorizedAt).toBe("number");
  });

  it("throws and clears cache on hash mismatch", async () => {
    const raw = new Uint8Array([9, 8, 7, 6]);
    const wrongHash =
      "0000000000000000000000000000000000000000000000000000000000000000";
    globalThis.fetch = vi.fn(async () => gzippedResponse(raw)) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-mismatch", wrongHash, () => {}, AUTH),
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

    const out = await ensureAsset(
      testUrl,
      "cache-key-cached",
      expected,
      () => {},
      AUTH,
    );
    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(fetchSpy).not.toHaveBeenCalled();

    const meta = await assetStore.getMeta("cache-key-cached");
    expect(meta?.sha256).toBe(expected);
    expect(meta?.manifestSha256).toBe(AUTH.manifestSha256);
  });

  it("throws synchronously when called with empty expectedSha256", async () => {
    const fetchSpy = vi.fn(async () =>
      gzippedResponse(new Uint8Array([1])),
    ) as typeof fetch;
    globalThis.fetch = fetchSpy;

    await expect(
      ensureAsset(testUrl, "cache-key-empty", "", () => {}, AUTH),
    ).rejects.toThrow(/without expected hash/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refreshes stale cache when manifest hash changed", async () => {
    const v1 = new Uint8Array([1, 1, 1, 1]);
    const v2 = new Uint8Array([2, 2, 2, 2]);
    await assetStore.put("cache-key-stale", v1);
    await assetStore.setMeta("cache-key-stale", {
      bytesWritten: v1.byteLength,
      sha256: sha256HexOf(v1),
      manifestSha256: AUTH.manifestSha256,
      manifestFetchedAt: AUTH.fetchedAt,
      authorizedAt: AUTH.fetchedAt,
    });

    const fetchSpy = vi.fn(async () => gzippedResponse(v2)) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const out = await ensureAsset(
      testUrl,
      "cache-key-stale",
      sha256HexOf(v2),
      () => {},
      AUTH_V2,
    );
    expect(Array.from(out)).toEqual(Array.from(v2));
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const cached = await assetStore.get("cache-key-stale");
    expect(Array.from(cached!)).toEqual(Array.from(v2));

    const meta = await assetStore.getMeta("cache-key-stale");
    expect(meta?.sha256).toBe(sha256HexOf(v2));
    expect(meta?.manifestSha256).toBe(AUTH_V2.manifestSha256);
    expect(meta?.manifestFetchedAt).toBe(AUTH_V2.fetchedAt);
  });

  it("rejects and empties cache when the refreshed download also mismatches", async () => {
    const v1 = new Uint8Array([1, 1, 1, 1]);
    const served = new Uint8Array([3, 3, 3, 3]);
    await assetStore.put("cache-key-stale-bad", v1);

    globalThis.fetch = vi.fn(async () => gzippedResponse(served)) as typeof fetch;

    const expectedV2 = sha256HexOf(new Uint8Array([2, 2, 2, 2]));
    await expect(
      ensureAsset(
        testUrl,
        "cache-key-stale-bad",
        expectedV2,
        () => {},
        AUTH_V2,
      ),
    ).rejects.toThrow(/hash mismatch/);

    const cached = await assetStore.get("cache-key-stale-bad");
    expect(cached).toBeNull();
  });

  it("handles identity encoding for un-gzipped assets", async () => {
    const raw = new Uint8Array([7, 7, 7, 7, 7]);
    const expected = sha256HexOf(raw);
    globalThis.fetch = vi.fn(
      async () =>
        new Response(raw.slice().buffer as ArrayBuffer, {
          status: 200,
          headers: { "Content-Length": String(raw.byteLength) },
        }),
    ) as typeof fetch;

    const out = await ensureAsset(
      "/smt-snapshot/smt.wasm",
      "cache-key-identity",
      expected,
      () => {},
      AUTH,
      { encoding: "identity" },
    );
    expect(Array.from(out)).toEqual(Array.from(raw));

    const cached = await assetStore.get("cache-key-identity");
    expect(Array.from(cached!)).toEqual(Array.from(raw));
  });

  it("throws and leaves no cache entry on non-2xx response", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response("oops", { status: 500, statusText: "Internal Server Error" }),
    ) as typeof fetch;

    await expect(
      ensureAsset(
        testUrl,
        "cache-key-500",
        sha256HexOf(new Uint8Array([1])),
        () => {},
        AUTH,
      ),
    ).rejects.toThrow(/500/);

    const cached = await assetStore.get("cache-key-500");
    expect(cached).toBeNull();
  });

  it("throws and clears cache on malformed gzip payload", async () => {
    const junk = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    globalThis.fetch = vi.fn(
      async () =>
        new Response(junk.buffer as ArrayBuffer, {
          status: 200,
          headers: { "Content-Length": String(junk.byteLength) },
        }),
    ) as typeof fetch;

    await expect(
      ensureAsset(
        testUrl,
        "cache-key-badgz",
        sha256HexOf(new Uint8Array([1])),
        () => {},
        AUTH,
      ),
    ).rejects.toThrow();

    const cached = await assetStore.get("cache-key-badgz");
    expect(cached).toBeNull();
  });
});
