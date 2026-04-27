// Streaming asset download + (optional) gzip decompress + SHA-256 verify.
//
// `expectedSha256` covers the **compressed** bytes (matches GitHub's
// per-release `digest`). Cache keys must embed that SHA so a key-hit doubles
// as proof of prior verification — no rehash on read.

import { sha256 } from "@noble/hashes/sha2.js";

import { assetStore } from "./asset-store";
import { bytesToHex } from "./bytes";

export interface DownloadProgress {
  bytesDone: number;
  bytesTotal: number;
}

export interface EnsureAssetOptions {
  /** `"gzip"` (default) decompresses before storing; `"identity"` stores verbatim. */
  encoding?: "gzip" | "identity";
}

export async function ensureAsset(
  url: string,
  cacheKey: string,
  expectedSha256: string,
  onProgress: (p: DownloadProgress) => void,
  options: EnsureAssetOptions = {},
): Promise<Uint8Array> {
  if (!expectedSha256) {
    throw new Error(`ensureAsset called without expected hash for ${cacheKey}`);
  }

  const cached = await assetStore.get(cacheKey);
  if (cached) return cached;

  const encoding = options.encoding ?? "gzip";

  let response: Response;
  try {
    response = await fetch(url);
  } catch (err) {
    throw new Error(`fetch failed for ${url}`, { cause: err });
  }
  if (!response.ok) {
    throw new Error(
      `fetch ${url} returned ${response.status} ${response.statusText}`,
    );
  }
  if (!response.body) {
    throw new Error(`fetch ${url} returned no body`);
  }

  const lenHeader = response.headers.get("Content-Length");
  // Progress is reported in the compressed domain — DecompressionStream doesn't
  // know the decompressed length up front.
  const bytesTotal = lenHeader ? parseInt(lenHeader, 10) : 0;
  let bytesDone = 0;

  const hasher = sha256.create();
  const compressedTap = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      bytesDone += chunk.byteLength;
      onProgress({ bytesDone, bytesTotal });
      hasher.update(chunk);
      controller.enqueue(chunk);
    },
  });

  const writer = await assetStore.writer(cacheKey);

  try {
    let stream = response.body.pipeThrough(compressedTap);
    if (encoding === "gzip") {
      stream = stream.pipeThrough(
        new DecompressionStream("gzip") as unknown as ReadableWritablePair<
          Uint8Array,
          Uint8Array
        >,
      );
    }
    await stream.pipeTo(writer);
  } catch (err) {
    await assetStore
      .delete(cacheKey)
      .catch((delErr) =>
        console.warn(`cleanup delete after pipeline failure failed for ${cacheKey}:`, delErr),
      );
    throw err;
  }

  const actual = bytesToHex(hasher.digest());
  if (actual !== expectedSha256) {
    // Await delete before throwing so an immediate retry doesn't race
    // assetStore.get() against the in-flight delete.
    await assetStore
      .delete(cacheKey)
      .catch((delErr) =>
        console.warn(`cleanup delete after hash mismatch failed for ${cacheKey}:`, delErr),
      );
    throw new Error(
      `hash mismatch for ${cacheKey}: expected ${expectedSha256}, got ${actual}`,
    );
  }

  const stored = await assetStore.get(cacheKey);
  if (!stored) {
    throw new Error(`asset disappeared after write for ${cacheKey}`);
  }

  await sweepStaleSiblings(cacheKey);
  return stored;
}

// Cache keys are <prefix>_<64-hex-sha>. Once the new SHA verifies, drop any
// sibling under the same prefix so old releases don't accumulate in OPFS.
const KEY_SHA_SUFFIX = /^(.*)_[0-9a-f]{64}$/;

async function sweepStaleSiblings(currentKey: string): Promise<void> {
  const m = KEY_SHA_SUFFIX.exec(currentKey);
  if (!m) return;
  const prefix = `${m[1]}_`;
  let siblings: string[];
  try {
    siblings = await assetStore.listKeys(prefix);
  } catch (err) {
    console.warn(`sibling sweep listKeys failed for ${prefix}:`, err);
    return;
  }
  for (const k of siblings) {
    if (k === currentKey) continue;
    if (!/_[0-9a-f]{64}$/.test(k)) continue;
    await assetStore
      .delete(k)
      .catch((err) =>
        console.warn(`sibling sweep delete failed for ${k}:`, err),
      );
  }
}
