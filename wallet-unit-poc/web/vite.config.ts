/// <reference types="vitest" />
import { defineConfig, loadEnv } from "vite";

const RELEASE_BASE = "https://github.com/zkmopro/zkID/releases/download/latest";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const SMT_TARGET = env.VITE_SMT_PROXY_TARGET ?? "http://localhost:3000";

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
        // moica-revocation-smt may or may not send CORS headers; proxy
        // to dodge the question.
        "/smt": {
          target: SMT_TARGET,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/smt/, ""),
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
