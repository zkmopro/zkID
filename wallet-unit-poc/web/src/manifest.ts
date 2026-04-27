// Asset manifest for proving keys, witness wasm, and SMT snapshots.
// Hydration is fail-closed: any unreachable / malformed / incomplete
// manifest aborts warmup so cached bytes are never trusted without a
// fresh authoritative hash.

import { bytesToHex } from "./bytes";
import type { SmtIssuer } from "./smt-client";

export type CircuitKind =
  | "cert_chain_rs2048"
  | "cert_chain_rs4096"
  | "device_sig_rs2048";

export interface CircuitManifest {
  kind: CircuitKind;
  numPublic: number;
  // /keys/<asset>.gz in dev (proxy), absolute URL in prod.
  pkUrl: string;
  witnessWasmUrl: string;
  // SHA-256 of decompressed bytes; populated by hydrateManifest().
  expected: { pk: string; witnessWasm: string };
}

export interface SmtAssetManifest {
  issuer: SmtIssuer;
  /** /smt-snapshot/<issuer>-tree-snapshot.bin.gz in dev. */
  snapshotUrl: string;
  /** SHA-256 of decompressed snapshot bytes; set by hydrateManifest(). */
  expectedSnapshot: string;
}

export const CIRCUITS: Record<CircuitKind, CircuitManifest> = {
  cert_chain_rs2048: {
    kind: "cert_chain_rs2048",
    numPublic: 20,
    pkUrl: "/keys/cert_chain_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/cert_chain_rs2048.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
  cert_chain_rs4096: {
    kind: "cert_chain_rs4096",
    numPublic: 37,
    pkUrl: "/keys/cert_chain_rs4096_proving.key.gz",
    witnessWasmUrl: "/keys/cert_chain_rs4096.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
  device_sig_rs2048: {
    kind: "device_sig_rs2048",
    numPublic: 2,
    pkUrl: "/keys/device_sig_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/device_sig_rs2048.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
};

export const SMT_SNAPSHOTS: Record<SmtIssuer, SmtAssetManifest> = {
  g2: {
    issuer: "g2",
    snapshotUrl: "/smt-snapshot/g2-tree-snapshot.bin.gz",
    expectedSnapshot: "",
  },
  g3: {
    issuer: "g3",
    snapshotUrl: "/smt-snapshot/g3-tree-snapshot.bin.gz",
    expectedSnapshot: "",
  },
};

/** Go SMT engine wasm (served raw, not gzipped). */
export const SMT_WASM = { url: "/smt-snapshot/smt.wasm", expected: "" };
/** Go wasm_exec.js loader (text). */
export const SMT_WASM_EXEC = { url: "/smt-snapshot/wasm_exec.js", expected: "" };

export const KEYS_MANIFEST_URL = "/keys/manifest.json";
export const SMT_MANIFEST_URL = "/smt-snapshot/snapshot-manifest.json";

export interface HydrationResult {
  keysManifestSha256: string;
  smtManifestSha256: string;
  fetchedAt: number;
}

export interface AuthorizingManifest {
  manifestSha256: string;
  fetchedAt: number;
}

export class ManifestUnreachableError extends Error {
  constructor(url: string, detail: string, options?: { cause?: unknown }) {
    super(`manifest unreachable: ${url} (${detail})`, options);
    this.name = "ManifestUnreachableError";
  }
}

export class ManifestMalformedError extends Error {
  constructor(url: string, reason: string, options?: { cause?: unknown }) {
    super(`manifest malformed: ${url} (${reason})`, options);
    this.name = "ManifestMalformedError";
  }
}

export class ManifestMissingAssetError extends Error {
  readonly assetName: string;
  constructor(assetName: string) {
    super(`manifest missing or invalid hash for asset: ${assetName}`);
    this.name = "ManifestMissingAssetError";
    this.assetName = assetName;
  }
}

export type ManifestErrorKind = "unreachable" | "malformed" | "missing_asset";

export function manifestErrorKind(err: unknown): ManifestErrorKind | undefined {
  if (err instanceof ManifestUnreachableError) return "unreachable";
  if (err instanceof ManifestMalformedError) return "malformed";
  if (err instanceof ManifestMissingAssetError) return "missing_asset";
  return undefined;
}

const HEX_64 = /^[0-9a-f]{64}$/;

interface PublishedManifest {
  assets: Record<string, { sha256_decompressed: string }>;
}

export function basename(url: string): string {
  const q = url.indexOf("?");
  const clean = q === -1 ? url : url.slice(0, q);
  const slash = clean.lastIndexOf("/");
  return slash === -1 ? clean : clean.slice(slash + 1);
}

async function fetchManifestText(url: string): Promise<string> {
  // ?t= defeats intermediate reverse-proxy / CDN caches keyed on full URL.
  const bust = `${url}${url.includes("?") ? "&" : "?"}t=${Date.now()}`;
  let response: Response;
  try {
    response = await fetch(bust, {
      cache: "no-store",
      headers: { "cache-control": "no-cache" },
    });
  } catch (err) {
    throw new ManifestUnreachableError(url, "fetch failed", { cause: err });
  }
  if (!response.ok) {
    throw new ManifestUnreachableError(
      url,
      `HTTP ${response.status} ${response.statusText}`,
    );
  }
  try {
    return await response.text();
  } catch (err) {
    throw new ManifestUnreachableError(url, "body read failed", { cause: err });
  }
}

function parseManifest(url: string, text: string): PublishedManifest {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ManifestMalformedError(url, "JSON parse failed", { cause: err });
  }
  if (!raw || typeof raw !== "object") {
    throw new ManifestMalformedError(url, "body is not an object");
  }
  const assets = (raw as { assets?: unknown }).assets;
  if (!assets || typeof assets !== "object" || Array.isArray(assets)) {
    throw new ManifestMalformedError(url, "missing or non-object `assets`");
  }
  return { assets: assets as PublishedManifest["assets"] };
}

function requireHash(manifest: PublishedManifest, assetName: string): string {
  const entry = manifest.assets[assetName] as
    | { sha256_decompressed?: unknown }
    | undefined;
  const hash =
    entry && typeof entry.sha256_decompressed === "string"
      ? entry.sha256_decompressed
      : undefined;
  if (!hash || !HEX_64.test(hash)) {
    throw new ManifestMissingAssetError(assetName);
  }
  return hash;
}

async function sha256HexOfText(text: string): Promise<string> {
  const encoded = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return bytesToHex(new Uint8Array(digest));
}

export async function hydrateManifest(): Promise<HydrationResult> {
  const [keysText, smtText] = await Promise.all([
    fetchManifestText(KEYS_MANIFEST_URL),
    fetchManifestText(SMT_MANIFEST_URL),
  ]);

  const keysManifest = parseManifest(KEYS_MANIFEST_URL, keysText);
  for (const key of Object.keys(CIRCUITS) as CircuitKind[]) {
    const m = CIRCUITS[key];
    m.expected.pk = requireHash(keysManifest, basename(m.pkUrl));
    m.expected.witnessWasm = requireHash(keysManifest, basename(m.witnessWasmUrl));
  }

  const smtManifest = parseManifest(SMT_MANIFEST_URL, smtText);
  for (const issuer of Object.keys(SMT_SNAPSHOTS) as SmtIssuer[]) {
    const m = SMT_SNAPSHOTS[issuer];
    m.expectedSnapshot = requireHash(smtManifest, basename(m.snapshotUrl));
  }
  SMT_WASM.expected = requireHash(smtManifest, basename(SMT_WASM.url));
  SMT_WASM_EXEC.expected = requireHash(smtManifest, basename(SMT_WASM_EXEC.url));

  const [keysManifestSha256, smtManifestSha256] = await Promise.all([
    sha256HexOfText(keysText),
    sha256HexOfText(smtText),
  ]);

  return { keysManifestSha256, smtManifestSha256, fetchedAt: Date.now() };
}
