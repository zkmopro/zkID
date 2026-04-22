// Asset manifest for proving keys, witness wasm, and SMT snapshots.
// Hashes are filled from runtime manifests; empty hash means "skip verification".
// Assets are expected to be served same-origin via /keys and /smt-snapshot.

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

interface PublishedManifest {
  assets: Record<string, { sha256_decompressed: string }>;
}

function basename(url: string): string {
  const q = url.indexOf("?");
  const clean = q === -1 ? url : url.slice(0, q);
  const slash = clean.lastIndexOf("/");
  return slash === -1 ? clean : clean.slice(slash + 1);
}

/** Overlay `/keys/manifest.json` hashes onto circuit entries; fail-open. */
export async function hydrateManifest(): Promise<void> {
  let body: PublishedManifest | null = null;
  try {
    const r = await fetch("/keys/manifest.json", { method: "GET" });
    if (!r.ok) {
      console.warn(
        `manifest.json fetch returned ${r.status} ${r.statusText}; hash verification disabled`,
      );
      return;
    }
    body = (await r.json()) as PublishedManifest;
  } catch (err) {
    console.warn("manifest.json fetch/parse failed; hash verification disabled:", err);
    return;
  }
  if (!body || typeof body !== "object" || !body.assets) {
    console.warn("manifest.json malformed (no `assets` object); hash verification disabled");
    return;
  }
  for (const key of Object.keys(CIRCUITS) as CircuitKind[]) {
    const m = CIRCUITS[key];
    const pkName = basename(m.pkUrl);
    const wgenName = basename(m.witnessWasmUrl);
    const pkEntry = body.assets[pkName];
    const wgenEntry = body.assets[wgenName];
    if (pkEntry && typeof pkEntry.sha256_decompressed === "string") {
      m.expected.pk = pkEntry.sha256_decompressed;
    } else {
      console.warn(`manifest.json missing entry for ${pkName}; PK hash verification disabled for ${key}`);
    }
    if (wgenEntry && typeof wgenEntry.sha256_decompressed === "string") {
      m.expected.witnessWasm = wgenEntry.sha256_decompressed;
    } else {
      console.warn(`manifest.json missing entry for ${wgenName}; witness-wasm hash verification disabled for ${key}`);
    }
  }

  await hydrateSmtManifest();
}

/** Overlay `/smt-snapshot/snapshot-manifest.json` hashes; also fail-open. */
async function hydrateSmtManifest(): Promise<void> {
  let body: PublishedManifest | null = null;
  try {
    const r = await fetch("/smt-snapshot/snapshot-manifest.json", {
      method: "GET",
    });
    if (!r.ok) {
      console.warn(
        `snapshot-manifest.json fetch returned ${r.status} ${r.statusText}; SMT hash verification disabled`,
      );
      return;
    }
    body = (await r.json()) as PublishedManifest;
  } catch (err) {
    console.warn(
      "snapshot-manifest.json fetch/parse failed; SMT hash verification disabled:",
      err,
    );
    return;
  }
  if (!body || typeof body !== "object" || !body.assets) {
    console.warn(
      "snapshot-manifest.json malformed (no `assets` object); SMT hash verification disabled",
    );
    return;
  }
  for (const issuer of Object.keys(SMT_SNAPSHOTS) as SmtIssuer[]) {
    const m = SMT_SNAPSHOTS[issuer];
    const name = basename(m.snapshotUrl);
    const entry = body.assets[name];
    if (entry && typeof entry.sha256_decompressed === "string") {
      m.expectedSnapshot = entry.sha256_decompressed;
    } else {
      console.warn(
        `snapshot-manifest.json missing entry for ${name}; snapshot hash verification disabled for ${issuer}`,
      );
    }
  }
  const wasmEntry = body.assets[basename(SMT_WASM.url)];
  if (wasmEntry && typeof wasmEntry.sha256_decompressed === "string") {
    SMT_WASM.expected = wasmEntry.sha256_decompressed;
  }
  const execEntry = body.assets[basename(SMT_WASM_EXEC.url)];
  if (execEntry && typeof execEntry.sha256_decompressed === "string") {
    SMT_WASM_EXEC.expected = execEntry.sha256_decompressed;
  }
}
