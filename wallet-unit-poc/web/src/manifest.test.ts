// Tests for manifest.ts: GitHub Release API digest fetch + parse, fail-closed.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  basename,
  CIRCUITS,
  fetchReleaseDigests,
  ManifestError,
  requireDigest,
  SMT_SNAPSHOTS,
  SMT_WASM,
  SMT_WASM_EXEC,
} from "./manifest";

const KEYS_API =
  "https://api.github.com/repos/zkmopro/zkID/releases/tags/latest";
const SMT_API =
  "https://api.github.com/repos/moven0831/moica-revocation-smt/releases/tags/snapshot-latest";

interface FakeAsset {
  name: string;
  digest: string;
}

function releaseBody(assets: FakeAsset[]): string {
  return JSON.stringify({ assets });
}

function fullKeysAssets(): FakeAsset[] {
  const out: FakeAsset[] = [];
  let n = 0;
  for (const kind of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
    out.push({
      name: basename(CIRCUITS[kind].pkUrl),
      digest: `sha256:${(n++).toString().padStart(64, "a")}`,
    });
    out.push({
      name: basename(CIRCUITS[kind].witnessWasmUrl),
      digest: `sha256:${(n++).toString().padStart(64, "b")}`,
    });
  }
  return out;
}

function fullSmtAssets(): FakeAsset[] {
  const out: FakeAsset[] = [];
  for (const issuer of Object.keys(SMT_SNAPSHOTS) as Array<keyof typeof SMT_SNAPSHOTS>) {
    out.push({
      name: basename(SMT_SNAPSHOTS[issuer].snapshotUrl),
      digest: `sha256:${"c".repeat(64)}`,
    });
  }
  out.push({ name: basename(SMT_WASM.url), digest: `sha256:${"d".repeat(64)}` });
  out.push({ name: basename(SMT_WASM_EXEC.url), digest: `sha256:${"e".repeat(64)}` });
  return out;
}

interface FetchCall {
  url: string;
  init: RequestInit | undefined;
}

function mockFetch(
  handlers: Record<string, () => Response>,
): { calls: FetchCall[]; restore: () => void } {
  const defaults: Record<string, () => Response> = {
    [KEYS_API]: () => new Response(releaseBody(fullKeysAssets()), { status: 200 }),
    [SMT_API]: () => new Response(releaseBody(fullSmtAssets()), { status: 200 }),
  };
  const merged: Record<string, () => Response> = { ...defaults, ...handlers };
  const calls: FetchCall[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    const pathOnly = url.split("?")[0];
    const handler = merged[pathOnly];
    if (!handler) throw new Error(`unexpected fetch: ${url}`);
    return handler();
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

describe("fetchReleaseDigests", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns digests for both releases on the happy path", async () => {
    const { calls, restore } = mockFetch({});
    try {
      const out = await fetchReleaseDigests();

      for (const kind of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
        expect(out.keys[basename(CIRCUITS[kind].pkUrl)]).toMatch(/^[0-9a-f]{64}$/);
        expect(out.keys[basename(CIRCUITS[kind].witnessWasmUrl)]).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(out.smt[basename(SMT_WASM.url)]).toMatch(/^[0-9a-f]{64}$/);
      expect(out.smt[basename(SMT_WASM_EXEC.url)]).toMatch(/^[0-9a-f]{64}$/);

      expect(calls.length).toBe(2);
      for (const call of calls) {
        expect(call.url).toMatch(/[?&]t=\d+/);
        expect(call.init?.cache).toBe("no-store");
      }
    } finally {
      restore();
    }
  });

  it("throws ManifestError on non-2xx", async () => {
    const { restore } = mockFetch({
      [KEYS_API]: () => new Response("nope", { status: 500, statusText: "Internal Server Error" }),
    });
    try {
      await expect(fetchReleaseDigests()).rejects.toBeInstanceOf(ManifestError);
    } finally {
      restore();
    }
  });

  it("throws ManifestError on network failure", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    try {
      await expect(fetchReleaseDigests()).rejects.toBeInstanceOf(ManifestError);
    } finally {
      globalThis.fetch = original;
    }
  });

  it("throws ManifestError on non-JSON body", async () => {
    const { restore } = mockFetch({
      [KEYS_API]: () => new Response("not json", { status: 200 }),
    });
    try {
      await expect(fetchReleaseDigests()).rejects.toBeInstanceOf(ManifestError);
    } finally {
      restore();
    }
  });

  it("throws ManifestError when `assets` is missing", async () => {
    const { restore } = mockFetch({
      [KEYS_API]: () => new Response(JSON.stringify({}), { status: 200 }),
    });
    try {
      await expect(fetchReleaseDigests()).rejects.toBeInstanceOf(ManifestError);
    } finally {
      restore();
    }
  });

  it("silently drops assets with malformed digest strings", async () => {
    const goodSha = "f".repeat(64);
    const assets: FakeAsset[] = [
      { name: "alpha.gz", digest: `sha256:${goodSha}` },
      { name: "beta.gz", digest: "not-sha256-anything" },
      { name: "gamma.gz", digest: "sha512:notthealgowewant" },
    ];
    const { restore } = mockFetch({
      [KEYS_API]: () => new Response(releaseBody(assets), { status: 200 }),
    });
    try {
      const out = await fetchReleaseDigests();
      expect(out.keys["alpha.gz"]).toBe(goodSha);
      expect(out.keys["beta.gz"]).toBeUndefined();
      expect(out.keys["gamma.gz"]).toBeUndefined();
    } finally {
      restore();
    }
  });
});

describe("requireDigest", () => {
  it("returns the hex when present", () => {
    expect(requireDigest({ "asset.gz": "a".repeat(64) }, "asset.gz")).toBe("a".repeat(64));
  });

  it("throws ManifestError when missing", () => {
    expect(() => requireDigest({}, "missing.gz")).toThrow(ManifestError);
  });

  it("throws ManifestError on non-hex value", () => {
    expect(() => requireDigest({ "x.gz": "not-hex" }, "x.gz")).toThrow(ManifestError);
  });
});
