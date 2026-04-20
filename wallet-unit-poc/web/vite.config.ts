/// <reference types="vitest" />
import { defineConfig } from "vite";
const RELEASE_BASE = "https://github.com/zkmopro/zkID/releases/download/latest";
export default defineConfig({
  build: { target: "es2020" },
  worker: { format: "es" },
  optimizeDeps: { esbuildOptions: { target: "es2020" } },
  test: {
    // Keep Playwright specs out of the vitest suite.
    exclude: ["node_modules/**", "dist/**", "e2e/**"],
  },
  server: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    fs: { allow: [".."] },
    proxy: {
      "/keys": {
        target: RELEASE_BASE,
        changeOrigin: true,
        followRedirects: true,
        rewrite: (p) => p.replace(/^\/keys/, ""),
      },
    },
  },
  preview: { // same headers for pnpm preview (used by Playwright)
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
});
