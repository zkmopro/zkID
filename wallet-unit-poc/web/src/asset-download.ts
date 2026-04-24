// Streaming asset download + gzip decompress + SHA-256 verify.

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
  expectedSha256: string,
  onProgress: (p: DownloadProgress) => void,
): Promise<Uint8Array> {
  let response: Response;
  try {
    response = await fetch(url, { cache: "no-cache" });
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
  const bytesTotal = lenHeader ? parseInt(lenHeader, 10) : 0;
  let bytesDone = 0;

  const progressTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      bytesDone += chunk.byteLength;
      onProgress({ bytesDone, bytesTotal });
      controller.enqueue(chunk);
    },
  });

  const collected: Uint8Array[] = [];
  const collectTransform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      collected.push(chunk.slice());
      controller.enqueue(chunk);
    },
  });

  const gunzip = new DecompressionStream("gzip") as unknown as ReadableWritablePair<
    Uint8Array,
    Uint8Array
  >;
  const sink = new WritableStream<Uint8Array>();

  await response.body
    .pipeThrough(progressTransform)
    .pipeThrough(gunzip)
    .pipeThrough(collectTransform)
    .pipeTo(sink);

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
      throw new Error(
        `hash mismatch for ${url}: expected ${expectedSha256}, got ${actual}`,
      );
    }
  }

  return bytes;
}
