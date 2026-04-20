# web — zkID in-browser prover

Vite + TypeScript app that runs cert-chain + device-sig Spartan2 proving fully
in the browser using [`../spartan2-wasm`](../spartan2-wasm). Verification is
**server-side** via [`go-zkid-verifier`](https://github.com/zkmopro/go-zkid-verifier/pull/8)
(the app POSTs the two proofs to `POST /link-verify`). A dedicated Web Worker
drives the pipeline; the main thread renders a seven-step progress list.

## Quickstart

```sh
cd wallet-unit-poc/web
pnpm install

# Build the WASM crate and copy its output into src/wasm/ + public/assets/.
pnpm build:wasm
pnpm copy:assets

# Copy .env.example → .env.local and point the four VITE_* URLs at your
# local services (verifier, HiPKI, SMT). See .env.example for details.
cp .env.example .env.local
pnpm dev
```

Open `http://localhost:5173` and click **Prove**. The first run downloads the
proving keys + witness-gen WASMs from the GitHub Release (proxied through the
Vite dev server to work around CORS) and caches them locally; subsequent runs
skip the download.

## Architecture

| Module                   | Responsibility                                                                 |
| ------------------------ | ------------------------------------------------------------------------------ |
| `src/manifest.ts`        | `CircuitKind` union + per-circuit URLs + SHA-256s fetched from `manifest.json` |
| `src/asset-store.ts`     | Storage abstraction: OPFS primary, IndexedDB fallback                          |
| `src/asset-download.ts`  | Streaming fetch → `DecompressionStream('gzip')` → `SubtleCrypto.digest` verify |
| `src/witness.ts`         | CJS→ESM shim for circom's `witness_calculator.js` (with strict-mode patch)     |
| `src/verifier-client.ts` | `POST /challenge` + `POST /link-verify` against `go-zkid-verifier`             |
| `src/hipki-client.ts`    | `GET /pkcs11info` + `POST /sign` against the user's HiPKI LocalSignServer      |
| `src/smt-client.ts`      | `GET /proof/{issuer}/{serial}` against moica-revocation-smt → circuit inputs   |
| `src/inputs.ts`          | Wraps wasm `build_split_inputs` → `{ certJson, deviceJson }`                   |
| `src/pipeline.ts`        | Main-thread orchestrator: challenge → sign → SMT → build → Worker.postMessage  |
| `src/pin.ts`             | Single-use PIN wrapper; redacts on every observable surface                    |
| `src/worker.ts`          | CPU/wasm-bound steps: preflight/download/load/witness/prove/submit             |
| `src/store.ts`           | Discriminated-union `AppState` + `transition` reducer (landing/setup/proving)  |
| `src/router.ts`          | Subscribes to `$state.phase` and swaps the mounted screen                      |
| `src/screens/*.ts`       | Landing / setup / proving screen mounts                                        |
| `src/setup-state.ts`     | `$hipki` + `$pin` atoms holding polling probe + verified PIN                   |
| `src/ui.ts`              | nanostores atoms + DOM paint for the step list                                 |
| `src/main.ts`            | Entry point: mount router, spawn Worker, bridge `phase = proving` to pipeline  |

Pipeline (mirrors `src/ui.ts::Step`):

```
preflight → challenge → sign → smt → build → download → load → witness → prove → submit → done
                                                                                           \\
                                                                                            error (at whichever step failed)
```

Main thread owns the network + HiPKI + input-build steps; the Worker owns
the CPU/wasm-bound ones. `preflight` initialises the WASM module + rayon
thread pool. `challenge` fetches server challenge bytes. `sign` asks HiPKI
to sign those bytes with the user's card. `smt` fetches the non-membership
proof. `build` calls wasm `build_split_inputs` to produce cert-chain +
device-sig JSON (byte-identical to the Rust CLI — drift-tested in CI).
`download` pulls proving keys + witness WASMs. `load` deserializes each
PK into the WASM prover state. `witness` generates the `.wtns` via
circom's JS calculator. `prove` runs Spartan2. `submit` POSTs both proofs
to `POST /link-verify` and surfaces the server's `verified` boolean.

## Asset sources

On click, the Worker resolves these URLs (all gzipped on the server):

- `/keys/cert_chain_rs2048_proving.key.gz` (or rs4096 if the cert input is 4096)
- `/keys/device_sig_rs2048_proving.key.gz`
- `/keys/cert_chain_rs2048.wasm.gz` (circom witness-gen)
- `/keys/device_sig_rs2048.wasm.gz`
- `/keys/manifest.json` (optional; adds SHA-256 verification when present)

In dev, `/keys/*` is proxied to `https://github.com/zkmopro/zkID/releases/download/latest/<asset>`
via `vite.config.ts`. In prod, configure your host to serve those assets from a
same-origin path (or adjust `src/manifest.ts` to an absolute URL you control).

Verifying keys are **not** downloaded to the browser — verification runs on the
Go server and it has its own copy.

## External services

Three services the browser talks to at runtime. Each is configurable via a
`VITE_*` env var (see `.env.example`):

| Service                 | Env var                  | Default     | Purpose                                      |
| ----------------------- | ------------------------ | ----------- | -------------------------------------------- |
| `go-zkid-verifier`      | `VITE_VERIFIER_BASE_URL` | `http://localhost:8080` | Challenge + `link-verify`        |
| HiPKI LocalSignServer   | `VITE_HIPKI_BASE_URL`    | `/hipki`    | `pkcs11info` + `sign` (proxied to localhost:61161) |
| `moica-revocation-smt`  | `VITE_SMT_BASE_URL`      | `/smt`      | SMT non-membership proofs (proxied to localhost:3000) |

Plus `VITE_SMT_ISSUER` (default `g2`, use `g3` for RSA-4096 issuer chains).

### HiPKI CORS + mixed-content (why we proxy)

HiPKI's LocalSignServer does **not** send `Access-Control-Allow-Origin`
headers. A direct `fetch("http://localhost:61161/pkcs11info")` from the
browser will return 200 *and* be blocked — the browser delivers an opaque
"net::ERR_FAILED 200 (OK)" error to JS and never lets the app see the body.

The `/hipki/*` proxy in `vite.config.ts` works around this by forwarding
through the Vite dev origin so the browser sees a same-origin request.
Same trick for `/smt/*`. Override the upstream targets via
`VITE_HIPKI_PROXY_TARGET` / `VITE_SMT_PROXY_TARGET` if your services run
on non-default ports.

If you host the web app over HTTPS, the browser will also refuse direct
`http://localhost:61161` requests under its mixed-content policy. The
proxy avoids this too — same-origin requests to `/hipki/*` ride the page's
own scheme. **For production deploys, the host serving the static bundle
must run an equivalent reverse proxy** so browser → host → user's
LocalSignServer all stays same-origin (see `## Production deployment`
below).

## Production deployment

Production needs three things the dev proxy provides for free:

1. **Cross-origin isolation headers** (`Cross-Origin-Opener-Policy:
   same-origin` + `Cross-Origin-Embedder-Policy: require-corp`) for
   SharedArrayBuffer / multi-threaded proving.
2. **A reverse proxy from `/hipki/*` to the user's `localhost:61161`** so
   browser fetches are same-origin and bypass HiPKI's missing CORS headers.
3. **A reverse proxy from `/smt/*`** to the SMT server (or set
   `VITE_SMT_BASE_URL` to an absolute URL on a CORS-enabled host).

A standard CDN (GitHub Pages, plain Netlify) can do (1) but not (2) — the
HiPKI server runs on the **user's** machine, not the CDN's. Two patterns
that work:

- **Hosted app + user-side mini-proxy.** Ship a small native helper
  (Caddy / nginx / a tiny Go binary) alongside the HiPKI installer that
  exposes `/hipki/*` on the same origin as the deployed app. The helper
  proxies into `localhost:61161` and adds the COOP/COEP headers.
- **Local-first app.** Ship the static bundle as part of the same
  installer that bundles HiPKI. The user runs everything on their own
  machine (`http://localhost:<port>`), and a tiny local server provides
  both the static files and the `/hipki/*` reverse proxy.

A pure cloud-hosted "any user can visit" deployment is **not viable**
without one of these helpers. The browser cannot reach the user's
localhost LocalSignServer from a remote origin under any combination of
CORS / mixed-content rules.

## Browser requirements

The app uses `SharedArrayBuffer` for multi-threaded proving, which requires
cross-origin isolation:

- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

Vite's dev server and `preview` set both; for production deploys, your host
must too (GitHub Pages cannot — use Cloudflare Pages, Netlify, Vercel, or a
custom server). At runtime the Worker checks `self.crossOriginIsolated` and
reports to the console.

## Thread-count policy

```
threads = clamp(navigator.hardwareConcurrency - 1, 2, 8)
```

Leave one core for the main thread so UI updates stay smooth during proving.
The 8-thread cap is not arbitrary: wasm32 has a 4 GB linear-memory ceiling and
`cert_chain_rs4096` proofs pressure it at higher thread counts. Override with
`?threads=<n>` on the URL if you want to experiment (clamped to `[1, 32]`).

## Storage inspection

Cached assets live in:

- **OPFS**: DevTools → Application → Storage → Origin Private File System.
  Each asset is stored at its cache key (e.g. `cert_chain_rs2048_pk`); meta
  lives at `.meta/<key>.json`.
- **IndexedDB fallback**: database `zkid-web-assets`, object stores `assets`
  and `meta`.

To force a re-download, delete the corresponding entry (or run
`navigator.storage.getDirectory().then(d => d.remove(...))` in the console).

## Tests

```sh
pnpm test         # Vitest — asset-download, verifier, hipki, smt client unit tests
pnpm lint         # tsc --noEmit under "strict": true
pnpm build        # Production bundle
pnpm test:e2e     # Playwright against pnpm preview (mock verifier)
```

The e2e suite under `e2e/`:

- **`prove-fixtures.spec.ts`** — runs on every PR. Intercepts
  `/challenge` + `/link-verify` with deterministic mocks. Fixture PKs are not
  bundled (they land with Phase 3 CI), so the pipeline reaches `step-error`
  at the download step on a bare checkout — the test accepts either terminal
  state (done or error) to prove the pipeline plumbing works.
- **`prove-real.spec.ts`** (`@real`) — gated by `E2E_MODE=real`. Runs against
  a live `go-zkid-verifier` and real Release keys. Nightly CI only.

Install browsers before first run: `pnpm exec playwright install --with-deps chromium`.

## Known limitations (v1)

- No resumable downloads. A failed fetch discards partial bytes; retry
  re-downloads from scratch. See `src/asset-download.ts` header comment.
- No `.partial` rename on writer commit — a crash mid-write can leave a
  truncated cache entry. The SHA-256 check on the next read catches this
  *only if* `manifest.json` was hydrated.
- `link_verify` runs server-side only; the WASM crate's `link_verify` export
  exists for the drift test but is not called from the production pipeline.
- No fetch timeouts yet — if HiPKI or SMT hangs, the setup screen hangs with
  it. Phase 5 adds `AbortSignal.timeout` + retry limiters.
