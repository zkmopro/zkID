import { defineConfig } from "vite";

export default defineConfig({
  // BigInt support requires ES2020+
  build: {
    target: "es2020",
  },
  worker: {
    format: "es",
  },
  optimizeDeps: {
    esbuildOptions: {
      target: "es2020",
    },
  },
  server: {
    headers: {
      // Required for SharedArrayBuffer (multi-threaded WASM via wasm-bindgen-rayon)
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    // Allow serving files from parent directories (openac-sdk source)
    fs: {
      allow: [".."],
    },
  },
});
