// Streaming asset download + (optional) gzip decompress + SHA-256 verify.
//
// `expectedSha256` covers the **compressed** bytes (matches GitHub's
// per-release `digest`). Cache keys must embed that SHA so a key-hit doubles
// as proof of prior verification — no rehash on read.

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

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = bytes.slice().buffer;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(digest));
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
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

  // SubtleCrypto.digest is one-shot, so accumulate compressed chunks for hashing.
  const compressedChunks: Uint8Array[] = [];
  const compressedTap = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      bytesDone += chunk.byteLength;
      onProgress({ bytesDone, bytesTotal });
      compressedChunks.push(chunk.slice());
      controller.enqueue(chunk);
    },
  });

  // Mirror the post-decompression bytes into memory so we can return them
  // without re-reading from disk after the writer closes.
  const decompressedChunks: Uint8Array[] = [];
  const collectTap = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      decompressedChunks.push(chunk.slice());
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
    await stream.pipeThrough(collectTap).pipeTo(writer);
  } catch (err) {
    await assetStore
      .delete(cacheKey)
      .catch((delErr) =>
        console.warn(`cleanup delete after pipeline failure failed for ${cacheKey}:`, delErr),
      );
    throw err;
  }

  const compressed = concatChunks(compressedChunks);
  const actual = await sha256Hex(compressed);
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

  return concatChunks(decompressedChunks);
}
