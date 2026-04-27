// Streaming asset download + (optional) gzip decompress + SHA-256 verify.
// v1 limitation: no resumable downloads — a failed fetch re-downloads from scratch.

import { assetStore } from "./asset-store";
import { bytesToHex } from "./bytes";
import type { AuthorizingManifest } from "./manifest";

export interface DownloadProgress {
  bytesDone: number;
  bytesTotal: number;
}

export interface EnsureAssetOptions {
  /** `"gzip"` (default) pipes through DecompressionStream; `"identity"` stores verbatim. */
  encoding?: "gzip" | "identity";
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = bytes.slice().buffer;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(digest));
}

export async function ensureAsset(
  url: string,
  cacheKey: string,
  expectedSha256: string,
  onProgress: (p: DownloadProgress) => void,
  authorizing: AuthorizingManifest,
  options: EnsureAssetOptions = {},
): Promise<Uint8Array> {
  const encoding = options.encoding ?? "gzip";
  if (expectedSha256 === "") {
    throw new Error(
      `ensureAsset called without expected hash for ${cacheKey}`,
    );
  }

  const cached = await assetStore.get(cacheKey);
  if (cached) {
    // Skip the rehash when the prior meta already attests to this manifest.
    const meta = await assetStore.getMeta(cacheKey).catch(() => null);
    const trusted =
      meta?.sha256 === expectedSha256 &&
      meta?.manifestSha256 === authorizing.manifestSha256;
    if (trusted) return cached;
    const actual = await sha256Hex(cached);
    if (actual === expectedSha256) {
      await recordAuthorizedMeta(cacheKey, cached.byteLength, expectedSha256, authorizing);
      return cached;
    }
    // writer() below will overwrite, but surface obvious delete failures.
    try {
      await assetStore.delete(cacheKey);
    } catch (err) {
      console.warn(`stale cache entry for ${cacheKey}; delete failed, overwriting via writer:`, err);
    }
  }

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
  // Progress is reported in the compressed domain — DecompressionStream
  // doesn't know the decompressed length up front.
  const bytesTotal = lenHeader ? parseInt(lenHeader, 10) : 0;
  let bytesDone = 0;

  const progressTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      bytesDone += chunk.byteLength;
      onProgress({ bytesDone, bytesTotal });
      controller.enqueue(chunk);
    },
  });

  // SubtleCrypto.digest is one-shot, so collect the full byte set for the final hash.
  const collected: Uint8Array[] = [];
  const collectTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      collected.push(chunk.slice());
      controller.enqueue(chunk);
    },
  });

  const writer = await assetStore.writer(cacheKey);

  try {
    let stream = response.body.pipeThrough(progressTransform);
    if (encoding === "gzip") {
      stream = stream.pipeThrough(
        new DecompressionStream("gzip") as unknown as ReadableWritablePair<
          Uint8Array,
          Uint8Array
        >,
      );
    }
    await stream.pipeThrough(collectTransform).pipeTo(writer);
  } catch (err) {
    await assetStore
      .delete(cacheKey)
      .catch((delErr) =>
        console.warn(`cleanup delete after pipeline failure failed for ${cacheKey}:`, delErr),
      );
    throw err;
  }

  let total = 0;
  for (const c of collected) total += c.byteLength;
  const bytes = new Uint8Array(total);
  {
    let off = 0;
    for (const c of collected) {
      bytes.set(c, off);
      off += c.byteLength;
    }
  }

  const actual = await sha256Hex(bytes);
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

  await recordAuthorizedMeta(cacheKey, total, expectedSha256, authorizing);
  return bytes;
}

async function recordAuthorizedMeta(
  cacheKey: string,
  bytesWritten: number,
  sha256: string,
  authorizing: AuthorizingManifest,
): Promise<void> {
  try {
    await assetStore.setMeta(cacheKey, {
      bytesWritten,
      sha256,
      manifestSha256: authorizing.manifestSha256,
      manifestFetchedAt: authorizing.fetchedAt,
      authorizedAt: Date.now(),
    });
  } catch (err) {
    console.warn(`setMeta failed for ${cacheKey}:`, err);
  }
}
