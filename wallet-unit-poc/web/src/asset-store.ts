// Asset storage: OPFS primary, IndexedDB fallback.
//
// v1 limitation: `writer(key)` writes directly to the final key, not to a
// `.partial` file that gets atomically renamed on close. If a write is
// interrupted, the partially-written bytes remain under the final key — the
// caller must verify the hash (see asset-download.ts) and delete on mismatch.
// Phase 2+ follow-up: write to `<key>.partial`, rename on successful close.

export interface AssetMeta {
  bytesWritten: number;
  sha256?: string;
}

export interface AssetStore {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  writer(key: string): Promise<WritableStream<Uint8Array>>;
  delete(key: string): Promise<void>;
  getMeta(key: string): Promise<AssetMeta | null>;
  setMeta(key: string, meta: AssetMeta): Promise<void>;
}

function hasOPFS(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "storage" in navigator &&
    navigator.storage != null &&
    typeof (navigator.storage as { getDirectory?: unknown }).getDirectory ===
      "function"
  );
}

// ---------------------------------------------------------------------------
// OPFS backend
// ---------------------------------------------------------------------------

const META_DIR = ".meta";

async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  return navigator.storage.getDirectory();
}

async function opfsMetaDir(): Promise<FileSystemDirectoryHandle> {
  const root = await opfsRoot();
  return root.getDirectoryHandle(META_DIR, { create: true });
}

const opfsStore: AssetStore = {
  async get(key) {
    try {
      const root = await opfsRoot();
      const handle = await root.getFileHandle(key, { create: false });
      const file = await handle.getFile();
      const buf = await file.arrayBuffer();
      return new Uint8Array(buf);
    } catch (err) {
      if ((err as DOMException).name === "NotFoundError") return null;
      throw err;
    }
  },
  async put(key, bytes) {
    await opfsStore.delete(key);
    const root = await opfsRoot();
    const handle = await root.getFileHandle(key, { create: true });
    const writable = await handle.createWritable();
    // Slice into a fresh ArrayBuffer so SharedArrayBuffer-backed inputs still
    // satisfy createWritable()'s BufferSource requirement.
    await writable.write(bytes.slice().buffer);
    await writable.close();
  },
  async writer(key) {
    await opfsStore.delete(key);
    const root = await opfsRoot();
    const handle = await root.getFileHandle(key, { create: true });
    // FileSystemWritableFileStream IS a real WritableStream on modern browsers.
    return (await handle.createWritable()) as unknown as WritableStream<Uint8Array>;
  },
  async delete(key) {
    try {
      const root = await opfsRoot();
      await root.removeEntry(key);
    } catch (err) {
      if ((err as DOMException).name !== "NotFoundError") throw err;
    }
    try {
      const meta = await opfsMetaDir();
      await meta.removeEntry(`${key}.json`);
    } catch (err) {
      if ((err as DOMException).name !== "NotFoundError") throw err;
    }
  },
  async getMeta(key) {
    try {
      const meta = await opfsMetaDir();
      const handle = await meta.getFileHandle(`${key}.json`, { create: false });
      const file = await handle.getFile();
      const text = await file.text();
      return JSON.parse(text) as AssetMeta;
    } catch (err) {
      if ((err as DOMException).name === "NotFoundError") return null;
      throw err;
    }
  },
  async setMeta(key, value) {
    const meta = await opfsMetaDir();
    const handle = await meta.getFileHandle(`${key}.json`, { create: true });
    const writable = await handle.createWritable();
    await writable.write(JSON.stringify(value));
    await writable.close();
  },
};

// ---------------------------------------------------------------------------
// IndexedDB backend
// ---------------------------------------------------------------------------

const DB_NAME = "zkid-assets";
const DB_VERSION = 1;
const BYTES_STORE = "assets";
const META_STORE = "meta";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(BYTES_STORE))
        db.createObjectStore(BYTES_STORE, { keyPath: "key" });
      if (!db.objectStoreNames.contains(META_STORE))
        db.createObjectStore(META_STORE, { keyPath: "key" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbRun<T>(
  stores: string | string[],
  mode: IDBTransactionMode,
  fn: (tx: IDBTransaction) => T | Promise<T>,
): Promise<T> {
  const db = await openDb();
  try {
    const tx = db.transaction(stores, mode);
    const result = await Promise.resolve(fn(tx));
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    return result;
  } finally {
    db.close();
  }
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

const idbStore: AssetStore = {
  get: (key) =>
    idbRun(BYTES_STORE, "readonly", async (tx) => {
      const row = await req<{ key: string; bytes: Uint8Array } | undefined>(
        tx.objectStore(BYTES_STORE).get(key),
      );
      return row ? row.bytes : null;
    }),
  async put(key, bytes) {
    await idbStore.delete(key);
    await idbRun(BYTES_STORE, "readwrite", (tx) =>
      req(tx.objectStore(BYTES_STORE).put({ key, bytes })),
    );
  },
  async writer(key) {
    await idbStore.delete(key);
    let chunks: Uint8Array[] = [];
    return new WritableStream<Uint8Array>({
      // Copy to detach from any underlying buffer the caller may mutate.
      write(chunk) { chunks.push(chunk.slice()); },
      async close() {
        let total = 0;
        for (const c of chunks) total += c.byteLength;
        const merged = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
        await idbStore.put(key, merged);
      },
      abort(reason) {
        // Drop buffered chunks so nothing gets committed on a torn-down pipe.
        // The cache key was deleted in start(); no partial bytes persist.
        chunks = [];
        console.warn(`asset-store writer aborted for ${key}:`, reason);
      },
    });
  },
  delete: (key) =>
    idbRun([BYTES_STORE, META_STORE], "readwrite", (tx) => {
      tx.objectStore(BYTES_STORE).delete(key);
      tx.objectStore(META_STORE).delete(key);
    }),
  getMeta: (key) =>
    idbRun(META_STORE, "readonly", async (tx) => {
      const row = await req<{ key: string; meta: AssetMeta } | undefined>(
        tx.objectStore(META_STORE).get(key),
      );
      return row ? row.meta : null;
    }),
  async setMeta(key, meta) {
    await idbRun(META_STORE, "readwrite", (tx) =>
      req(tx.objectStore(META_STORE).put({ key, meta })),
    );
  },
};

export const assetStore: AssetStore = hasOPFS() ? opfsStore : idbStore;
