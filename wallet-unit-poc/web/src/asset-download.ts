// Streaming asset download + gzip decompress + SHA-256 verify.
//
// v1 limitation: no resumable downloads (no Range header). A failed or aborted
// fetch discards the partial write and re-downloads from scratch on retry.
// Phase 2+ follow-up: persist `bytesWritten` via assetStore.setMeta(), send
// `Range: bytes=<bytesWritten>-` on retry, and resume into the writer.

import { assetStore } from "./asset-store";
import { bytesToHex } from "./bytes";

export interface DownloadProgress {
  bytesDone: number;
  bytesTotal: number;
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
): Promise<Uint8Array> {
  // 1. Cache hit?
  const cached = await assetStore.get(cacheKey);
  if (cached) {
    if (expectedSha256 === "") return cached;
    const actual = await sha256Hex(cached);
    if (actual === expectedSha256) return cached;
    // Stale cache entry. Try to delete, but don't hard-fail if the delete itself
    // errors — writer() below will delete again, and surfacing a cleanup error
    // here would mask the actual re-download outcome.
    try {
      await assetStore.delete(cacheKey);
    } catch (err) {
      console.warn(`stale cache entry for ${cacheKey}; delete failed, overwriting via writer:`, err);
    }
  }

  // 2. Download.
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
  // Content-Length reflects the compressed size. DecompressionStream makes the
  // decompressed length unknown up front, so progress is reported in the
  // compressed domain.
  const bytesTotal = lenHeader ? parseInt(lenHeader, 10) : 0;
  let bytesDone = 0;

  // Track compressed progress before decompression.
  const progressTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      bytesDone += chunk.byteLength;
      onProgress({ bytesDone, bytesTotal });
      controller.enqueue(chunk);
    },
  });

  // Collect decompressed bytes into memory while simultaneously piping them
  // to the asset-store writer. SubtleCrypto.digest is one-shot; the hash
  // runs over the collected buffer at the end rather than streaming.
  const collected: Uint8Array[] = [];
  const collectTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      collected.push(chunk.slice());
      controller.enqueue(chunk);
    },
  });

  const writer = await assetStore.writer(cacheKey);

  try {
    // DecompressionStream's writable side types as WritableStream<BufferSource>
    // rather than WritableStream<Uint8Array>; cast to the concrete Uint8Array
    // pair used by the surrounding pipeline. Runtime accepts Uint8Array chunks.
    const gunzip = new DecompressionStream("gzip") as unknown as ReadableWritablePair<
      Uint8Array,
      Uint8Array
    >;
    await response.body
      .pipeThrough(progressTransform)
      .pipeThrough(gunzip)
      .pipeThrough(collectTransform)
      .pipeTo(writer);
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

  if (expectedSha256 !== "") {
    const actual = await sha256Hex(bytes);
    if (actual !== expectedSha256) {
      // Await the delete before throwing. Without the await, a caller that
      // retries immediately can race assetStore.get() against the in-flight
      // delete and read the corrupted bytes.
      await assetStore
        .delete(cacheKey)
        .catch((delErr) =>
          console.warn(`cleanup delete after hash mismatch failed for ${cacheKey}:`, delErr),
        );
      throw new Error(
        `hash mismatch for ${cacheKey}: expected ${expectedSha256}, got ${actual}`,
      );
    }
  }

  return bytes;
}
