// Asset storage: OPFS primary, IndexedDB fallback.
//
// Cache keys embed the upstream SHA-256 — a key-hit implies the bytes were
// verified at write-time, so no rehash on read. `listKeys(prefix)` lets
// callers find and reap orphaned entries from prior releases.

export interface AssetStore {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  writer(key: string): Promise<WritableStream<Uint8Array>>;
  delete(key: string): Promise<void>;
  listKeys(prefix: string): Promise<string[]>;
  clearAll(): Promise<void>;
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

async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  return navigator.storage.getDirectory();
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
    // .slice().buffer gives createWritable() a plain ArrayBuffer — required
    // because SharedArrayBuffer-backed views are rejected.
    await writable.write(bytes.slice().buffer);
    await writable.close();
  },
  async writer(key) {
    await opfsStore.delete(key);
    const root = await opfsRoot();
    const handle = await root.getFileHandle(key, { create: true });
    return (await handle.createWritable()) as unknown as WritableStream<Uint8Array>;
  },
  async delete(key) {
    try {
      const root = await opfsRoot();
      await root.removeEntry(key);
    } catch (err) {
      if ((err as DOMException).name !== "NotFoundError") throw err;
    }
  },
  async listKeys(prefix) {
    const root = await opfsRoot();
    const iter = (
      root as unknown as {
        [Symbol.asyncIterator](): AsyncIterableIterator<[string, FileSystemHandle]>;
      }
    )[Symbol.asyncIterator]();
    const names: string[] = [];
    for (;;) {
      const next = await iter.next();
      if (next.done) break;
      const name = next.value[0];
      if (name.startsWith(prefix)) names.push(name);
    }
    return names;
  },
  async clearAll() {
    const root = await opfsRoot();
    const iter = (
      root as unknown as {
        [Symbol.asyncIterator](): AsyncIterableIterator<[string, FileSystemHandle]>;
      }
    )[Symbol.asyncIterator]();
    const names: string[] = [];
    for (;;) {
      const next = await iter.next();
      if (next.done) break;
      names.push(next.value[0]);
    }
    for (const name of names) {
      try {
        await root.removeEntry(name, { recursive: true });
      } catch (err) {
        if ((err as DOMException).name !== "NotFoundError") throw err;
      }
    }
  },
};

// ---------------------------------------------------------------------------
// IndexedDB backend
// ---------------------------------------------------------------------------

const DB_NAME = "zkid-assets";
const DB_VERSION = 1;
const BYTES_STORE = "assets";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(BYTES_STORE))
        db.createObjectStore(BYTES_STORE, { keyPath: "key" });
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
        chunks = [];
        console.warn(`asset-store writer aborted for ${key}:`, reason);
      },
    });
  },
  delete: (key) =>
    idbRun(BYTES_STORE, "readwrite", (tx) => {
      tx.objectStore(BYTES_STORE).delete(key);
    }),
  listKeys: (prefix) =>
    idbRun(BYTES_STORE, "readonly", async (tx) => {
      // U+FFFF is the highest BMP code point — bounds every prefix-extending key.
      const range = IDBKeyRange.bound(prefix, prefix + "￿", false, false);
      const keys = await req<IDBValidKey[]>(
        tx.objectStore(BYTES_STORE).getAllKeys(range),
      );
      return keys.map(String);
    }),
  async clearAll() {
    await new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase(DB_NAME);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
      r.onblocked = () =>
        reject(new Error(`deleteDatabase blocked for ${DB_NAME}`));
    });
  },
};

export const assetStore: AssetStore = hasOPFS() ? opfsStore : idbStore;

export async function clearAllAssets(): Promise<void> {
  await assetStore.clearAll();
}
