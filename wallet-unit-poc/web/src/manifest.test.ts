// Tests for manifest.ts fail-closed hydration + cache-busting.

import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  basename,
  CIRCUITS,
  hydrateManifest,
  KEYS_MANIFEST_URL,
  ManifestMalformedError,
  ManifestMissingAssetError,
  ManifestUnreachableError,
  SMT_MANIFEST_URL,
  SMT_SNAPSHOTS,
  SMT_WASM,
  SMT_WASM_EXEC,
} from "./manifest";

function hashHex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function freshHash(seed: string): string {
  return hashHex(`zkid-test-${seed}`);
}

function goodKeysManifestJson(): string {
  const assets: Record<string, { sha256_decompressed: string }> = {};
  for (const kind of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
    const m = CIRCUITS[kind];
    assets[basename(m.pkUrl)] = { sha256_decompressed: freshHash(`${kind}-pk`) };
    assets[basename(m.witnessWasmUrl)] = {
      sha256_decompressed: freshHash(`${kind}-wgen`),
    };
  }
  return JSON.stringify({ assets });
}

function goodSmtManifestJson(): string {
  const assets: Record<string, { sha256_decompressed: string }> = {};
  for (const issuer of Object.keys(SMT_SNAPSHOTS) as Array<
    keyof typeof SMT_SNAPSHOTS
  >) {
    assets[basename(SMT_SNAPSHOTS[issuer].snapshotUrl)] = {
      sha256_decompressed: freshHash(`smt-${issuer}`),
    };
  }
  assets[basename(SMT_WASM.url)] = { sha256_decompressed: freshHash("smt-wasm") };
  assets[basename(SMT_WASM_EXEC.url)] = {
    sha256_decompressed: freshHash("wasm-exec"),
  };
  return JSON.stringify({ assets });
}

interface FetchCall {
  url: string;
  init: RequestInit | undefined;
}

function mockFetch(
  handlers: Record<string, () => Response | Promise<Response>>,
): { calls: FetchCall[]; restore: () => void } {
  // Defaults so tests targeting one manifest don't have to also stub the
  // other (hydrateManifest fetches both in parallel).
  const defaults: Record<string, () => Response> = {
    [KEYS_MANIFEST_URL]: () =>
      new Response(goodKeysManifestJson(), { status: 200 }),
    [SMT_MANIFEST_URL]: () =>
      new Response(goodSmtManifestJson(), { status: 200 }),
  };
  const merged: Record<string, () => Response | Promise<Response>> = {
    ...defaults,
    ...handlers,
  };
  const calls: FetchCall[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    const pathOnly = url.split("?")[0];
    const handler = merged[pathOnly];
    if (!handler) {
      throw new Error(`unexpected fetch: ${url}`);
    }
    return handler();
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

function resetCircuitExpectations(): void {
  for (const kind of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
    CIRCUITS[kind].expected.pk = "";
    CIRCUITS[kind].expected.witnessWasm = "";
  }
  for (const issuer of Object.keys(SMT_SNAPSHOTS) as Array<
    keyof typeof SMT_SNAPSHOTS
  >) {
    SMT_SNAPSHOTS[issuer].expectedSnapshot = "";
  }
  SMT_WASM.expected = "";
  SMT_WASM_EXEC.expected = "";
}

describe("hydrateManifest", () => {
  afterEach(() => {
    resetCircuitExpectations();
  });

  it("populates every expected hash and returns manifest digests on happy path", async () => {
    const keysJson = goodKeysManifestJson();
    const smtJson = goodSmtManifestJson();
    const { calls, restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () =>
        new Response(keysJson, { status: 200 }),
      [SMT_MANIFEST_URL]: () =>
        new Response(smtJson, { status: 200 }),
    });

    try {
      const result = await hydrateManifest();

      expect(result.keysManifestSha256).toBe(hashHex(keysJson));
      expect(result.smtManifestSha256).toBe(hashHex(smtJson));
      expect(typeof result.fetchedAt).toBe("number");

      for (const kind of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
        expect(CIRCUITS[kind].expected.pk).toMatch(/^[0-9a-f]{64}$/);
        expect(CIRCUITS[kind].expected.witnessWasm).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(SMT_WASM.expected).toMatch(/^[0-9a-f]{64}$/);
      expect(SMT_WASM_EXEC.expected).toMatch(/^[0-9a-f]{64}$/);

      expect(calls.length).toBe(2);
      for (const call of calls) {
        expect(call.url).toMatch(/[?&]t=\d+/);
        expect(call.init?.cache).toBe("no-store");
      }
    } finally {
      restore();
    }
  });

  it("throws ManifestUnreachableError on non-2xx response", async () => {
    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () =>
        new Response("nope", { status: 500, statusText: "Internal Server Error" }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestUnreachableError,
      );
    } finally {
      restore();
    }
  });

  it("throws ManifestUnreachableError on network failure", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("network down");
    }) as typeof fetch;

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestUnreachableError,
      );
    } finally {
      globalThis.fetch = original;
    }
  });

  it("throws ManifestMalformedError on non-JSON body", async () => {
    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () =>
        new Response("not json", { status: 200 }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestMalformedError,
      );
    } finally {
      restore();
    }
  });

  it("throws ManifestMalformedError when `assets` is missing", async () => {
    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () =>
        new Response(JSON.stringify({ version: 1 }), { status: 200 }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestMalformedError,
      );
    } finally {
      restore();
    }
  });

  it("throws ManifestMissingAssetError when a circuit entry is absent", async () => {
    const parsed = JSON.parse(goodKeysManifestJson()) as {
      assets: Record<string, unknown>;
    };
    const firstKind = Object.keys(CIRCUITS)[0] as keyof typeof CIRCUITS;
    delete parsed.assets[basename(CIRCUITS[firstKind].pkUrl)];
    const body = JSON.stringify(parsed);

    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () => new Response(body, { status: 200 }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestMissingAssetError,
      );
    } finally {
      restore();
    }
  });

  it("throws ManifestMissingAssetError on non-hex `sha256_decompressed`", async () => {
    const parsed = JSON.parse(goodKeysManifestJson()) as {
      assets: Record<string, { sha256_decompressed: string }>;
    };
    const firstKind = Object.keys(CIRCUITS)[0] as keyof typeof CIRCUITS;
    parsed.assets[basename(CIRCUITS[firstKind].pkUrl)] = {
      sha256_decompressed: "not-hex",
    };
    const body = JSON.stringify(parsed);

    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () => new Response(body, { status: 200 }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestMissingAssetError,
      );
    } finally {
      restore();
    }
  });

  it("throws ManifestMissingAssetError when the SMT manifest drops the Go wasm entry", async () => {
    const parsed = JSON.parse(goodSmtManifestJson()) as {
      assets: Record<string, unknown>;
    };
    delete parsed.assets[basename(SMT_WASM.url)];
    const body = JSON.stringify(parsed);

    const { restore } = mockFetch({
      [KEYS_MANIFEST_URL]: () =>
        new Response(goodKeysManifestJson(), { status: 200 }),
      [SMT_MANIFEST_URL]: () => new Response(body, { status: 200 }),
    });

    try {
      await expect(hydrateManifest()).rejects.toBeInstanceOf(
        ManifestMissingAssetError,
      );
    } finally {
      restore();
    }
  });
});
