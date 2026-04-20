/// <reference types="vitest" />
import { defineConfig, loadEnv } from "vite";

const RELEASE_BASE = "https://github.com/zkmopro/zkID/releases/download/latest";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const HIPKI_TARGET = env.VITE_HIPKI_PROXY_TARGET ?? "http://localhost:61161";
  const SMT_TARGET = env.VITE_SMT_PROXY_TARGET ?? "http://localhost:3000";
  const VERIFIER_TARGET =
    env.VITE_VERIFIER_PROXY_TARGET ?? "http://localhost:8080";

  return {
    build: { target: "es2020" },
    worker: { format: "es" },
    optimizeDeps: { esbuildOptions: { target: "es2020" } },
    test: {
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
        // HiPKI LocalSignServer doesn't send CORS headers, so the browser
        // blocks every direct cross-origin call even though the server
        // returns 200. Proxy through Vite's dev origin so requests are
        // same-origin from the browser's perspective.
        "/hipki": {
          target: HIPKI_TARGET,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/hipki/, ""),
        },
        // moica-revocation-smt likely won't send CORS headers either.
        "/smt": {
          target: SMT_TARGET,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/smt/, ""),
        },
        // go-zkid-verifier — proxied for symmetry. Set its base URL to
        // `/verifier` to opt in.
        "/verifier": {
          target: VERIFIER_TARGET,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/verifier/, ""),
        },
      },
    },
    preview: {
      headers: {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
      },
    },
  };
});
