// Circuit manifest — source of truth mapping CircuitKind to Release asset URLs
// and the SHA-256 hashes of the *decompressed* bytes. Hashes start empty and
// are overlaid at runtime from /keys/manifest.json (published by CI in Phase 3).
// If manifest.json is absent, hash verification is skipped so the app still
// runs against local fixtures served by the dev proxy.

export type CircuitKind =
  | "cert_chain_rs2048"
  | "cert_chain_rs4096"
  | "device_sig_rs2048";

export interface CircuitManifest {
  kind: CircuitKind;
  numPublic: number;
  // /keys/<asset>.gz in dev (proxied to GitHub Release); absolute in prod.
  pkUrl: string;
  witnessWasmUrl: string;
  // SHA-256 of the *decompressed* bytes. Populated by hydrateManifest().
  expected: { pk: string; witnessWasm: string };
}

export const CIRCUITS: Record<CircuitKind, CircuitManifest> = {
  cert_chain_rs2048: {
    kind: "cert_chain_rs2048",
    numPublic: 21,
    pkUrl: "/keys/cert_chain_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/cert_chain_rs2048.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
  cert_chain_rs4096: {
    kind: "cert_chain_rs4096",
    numPublic: 38,
    pkUrl: "/keys/cert_chain_rs4096_proving.key.gz",
    witnessWasmUrl: "/keys/cert_chain_rs4096.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
  device_sig_rs2048: {
    kind: "device_sig_rs2048",
    numPublic: 51,
    pkUrl: "/keys/device_sig_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/device_sig_rs2048.wasm.gz",
    expected: { pk: "", witnessWasm: "" },
  },
};

interface PublishedManifest {
  assets: Record<string, { sha256_decompressed: string }>;
}

function basename(url: string): string {
  const q = url.indexOf("?");
  const clean = q === -1 ? url : url.slice(0, q);
  const slash = clean.lastIndexOf("/");
  return slash === -1 ? clean : clean.slice(slash + 1);
}

/** Fetch the published manifest.json and overlay expected hashes on CIRCUITS.
 *  Never throws: a missing/malformed manifest simply leaves hashes empty and
 *  downstream code treats empty-string as "skip hash verification".
 *  Log messages distinguish fetch-level failures (network/CORS/non-2xx) from
 *  parse-level failures so ops can tell "server gave us nothing" from "server
 *  gave us something unintelligible". */
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
}
