/// <reference types="vitest" />
import { defineConfig, loadEnv } from "vite";

const RELEASE_BASE = "https://github.com/zkmopro/zkID/releases/download/latest";
const SMT_SNAPSHOT_RELEASE_BASE =
  "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const SMT_SNAPSHOT_TARGET =
    env.VITE_SMT_SNAPSHOT_PROXY_TARGET ?? SMT_SNAPSHOT_RELEASE_BASE;

  return {
    build: { target: "es2020" },
    worker: { format: "es" },
    optimizeDeps: { esbuildOptions: { target: "es2020" } },
    test: {
      exclude: ["node_modules/**", "dist/**", "e2e/**"],
    },
    server: {
      headers: {
        // `same-origin-allow-popups` preserves `window.opener` for the
        // HiPKI popupForm bridge while still scoping cross-origin tabs.
        // Strict `same-origin` would sever `opener` for the popup.
        "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
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
        // HiPKI is reached via the popupForm postMessage bridge (see
        // `src/hipki-popup.ts`), not through a proxy — the popup is
        // same-origin with the LocalSignServer at localhost:61161 and
        // its fetches don't need CORS headers.
        // SMT snapshot assets (smt.wasm, wasm_exec.js, per-issuer
        // *.bin.gz) come from the moica-revocation-smt `snapshot-latest`
        // release. Same shape as /keys: same-origin in dev via this
        // proxy, same-origin in prod via a deployer-configured reverse
        // proxy. We never rely on GitHub Release CORS headers.
        "/smt-snapshot": {
          target: SMT_SNAPSHOT_TARGET,
          changeOrigin: true,
          followRedirects: true,
          rewrite: (p) => p.replace(/^\/smt-snapshot/, ""),
        },
      },
    },
    preview: {
      headers: {
        // `same-origin-allow-popups` preserves `window.opener` for the
        // HiPKI popupForm bridge while still scoping cross-origin tabs.
        // Strict `same-origin` would sever `opener` for the popup.
        "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
        "Cross-Origin-Embedder-Policy": "require-corp",
      },
    },
  };
});
