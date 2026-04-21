# zkID Web Prover — Architecture

This document covers the in-browser zkID prover that lives at
`wallet-unit-poc/web/`. It captures decisions a fresh contributor needs in
order to extend or debug the system without re-deriving them from the
source: the popupForm bridge, the cross-origin isolation tradeoff, the
Worker thread model, the FSM, and the input-builder drift guard.

The companion crate is `wallet-unit-poc/spartan2-wasm/` (the wasm-bindgen
shim around `ecdsa-spartan2`). Verification runs server-side at
`go-zkid-verifier`; the wasm crate's `verify` / `link_verify` exist only
for the drift test.

## Goals and non-goals

**Goals.**

- Prove RS256 cert-chain + device-sig in a stock browser tab against a real
  Taiwan Citizen Card via HiPKI LocalSignServer, hand the proofs to
  `go-zkid-verifier`, and surface a `verified=true` to the user.
- No personal data on the page. PIN never leaves the popup origin or the
  Pin wrapper. Card serial is the only identifier rendered.
- Byte-for-byte parity with the native CLI's `generate_split_inputs` so a
  proof produced in the browser would also verify on the server given the
  same inputs.

**Non-goals.**

- In-browser verification (server owns trust anchors and revocation truth).
- Cancellable wasm work (Worker terminates and respawns instead — see
  "Cancellation").
- Production CORS handling (the popup bridge sidesteps it; a future hosted
  HiPKI gateway is the long-term answer).

## High-level data flow

```
landing  →  setup  →  proving  →  result
                       │
                       ├── main thread:  challenge → sign → smt → build inputs
                       │                  (HiPKI popup) (worker RPC) (zkid-input-builder via wasm)
                       │
                       └── Worker:       preflight → download → load → load_smt → smt_proof → witness → prove → submit
                                          (asset cache)        (PK)    (Go smt.wasm + snapshot) (witnesscalc) (Spartan2) (verifier)
```

Revocation is local. During setup, after HiPKI returns the card's issuer,
the Worker downloads the per-issuer SMT snapshot from
`moica-revocation-smt` release `snapshot-latest`, loads the Go-compiled
`smt.wasm`, and rebuilds the tree in memory. The `smt` step in the proving
pipeline is a main-thread → Worker RPC; no network traffic. See
"Revocation proof (local-first)" below.

The main thread owns network + HiPKI + input building. The Worker owns
CPU/wasm work. They communicate via a tiny `WorkerInMsg` /
`Progress` contract in `src/worker.ts`.

## The popupForm bridge

HiPKI LocalSignServer ships at `http://localhost:61161` with no CORS
headers. A direct `fetch()` from any other origin returns 200 but is
blocked by the browser before the body lands. The official HiPKI workaround
is `popupForm`: a tiny HTML page LocalSignServer hosts at `/popupForm`.
Because that page IS hosted at `localhost:61161`, its own XHRs to the local
API are same-origin and unblocked. Our app talks to the popup via
`window.postMessage`, which works across origins by design.

Implementation lives in `src/hipki-popup.ts`. Each request:

1. `window.open('http://localhost:61161/popupForm')` — must run in a
   user-gesture handler, otherwise the browser blocks the popup.
2. The popup posts `JSON.stringify({func:"getTbs"})` to `window.opener`
   when it's ready to accept commands.
3. We post `JSON.stringify(payload)` back; `payload.func` selects the
   action (`CheckEnvir`, `GetUserCert`, `MakeSignature`).
4. The popup runs the operation, posts the raw responseText back, and
   calls `window.close()` on itself.

**Single-shot per popup.** Each request needs its own popup because the
popup self-closes after one response. Polling through this bridge is not
possible — every probe would need a click. The setup UI is structured
around that: a "Detect readers" button enumerates slots, then a "Read
card" button reads the chosen slot's cert. PIN verify is its own click.

**Origin filter is strict.** Browser extensions postMessage objects into
every window. Anything that isn't from the popup's origin or isn't a
string is dropped. The "[object Object]" parse error visible in
LocalSignServer's own console is one of those — harmless and out of our
control.

## Cross-Origin isolation — two-route COOP

The HiPKI popup requires `Cross-Origin-Opener-Policy:
same-origin-allow-popups` so the popup's script can reach back into the
main page via `window.opener.postMessage`. The stricter `same-origin`
value severs the opener and breaks the bridge.

The rayon thread pool (`wasm-bindgen-rayon`) needs `SharedArrayBuffer`,
which only exists when `crossOriginIsolated === true`, which requires
`COOP: same-origin` + `COEP: require-corp`. These two requirements look
contradictory, but HiPKI and proving are strictly disjoint in time —
signing is done before proving starts — so each phase can live in its
own document with its own COOP.

The app ships as **two same-origin entry points**:

| Route       | COOP                         | `crossOriginIsolated` | Responsibility                                |
| ----------- | ---------------------------- | --------------------- | --------------------------------------------- |
| `/`         | `same-origin-allow-popups`   | `false`               | Landing, setup, ready, HiPKI sign, SMT, build |
| `/prove`    | `same-origin`                | `true`                | Worker warmup + witness + prove (threaded)    |

- `index.html` loads `src/sign-main.ts`. All screens up to and including
  the sign-phase pipeline (challenge → sign → SMT → build) run here.
- `prove.html` loads `src/prove-main.ts`. It reads a `ProveInput` that
  `/` wrote to `sessionStorage` (see `src/storage-handoff.ts`), spawns a
  fresh Worker inside the isolated context, runs warmup (fast — OPFS is
  origin-scoped and already contains the PK bytes from `/`), then posts
  `{type:"prove"}`. `clampThreads` in `src/worker.ts` returns a pool
  size ≥ 2 here because `crossOriginIsolated === true`.

The path-scoped headers are enforced in dev by the `coopPerPath` plugin
in `vite.config.ts` and in prod by the host (`public/_headers` is read
by Netlify / Cloudflare Pages; nginx / CDN snippets live in the
`web/README.md`). Hosts that can't scope headers by path fall back to
serving `same-origin-allow-popups` everywhere, which keeps the app
working at reduced speed — `clampThreads` returns 1 when isolation is
off and the pipeline degrades cleanly to single-threaded proving.

Data handoff between the two documents is a single `sessionStorage`
entry holding the built `ProveInput` (two input JSONs + circuit kind +
challenge id + nullifier). `sessionStorage` is same-origin, survives a
hard navigation, and is cleared by `consumeProveInput` on a successful
read so a `/prove` reload can't replay a stale run.

## State machine

The single source of truth for "what screen am I on" is the discriminated
union in `src/store.ts`:

```
landing → setup → proving → result
                          ↘
                            error
```

`reset` returns any state to `landing`. The router (`src/router.ts`)
subscribes to `$state.phase` and mounts the matching screen. Per-step
progress atoms (challenge / sign / smt / build / download / load /
witness / prove / submit) live in `src/ui.ts` and are driven by the
pipeline + Worker.

Setup-screen state (`HipkiState`, `PinState`) lives outside the FSM in
`src/setup-state.ts` so a Retry from `result` doesn't force re-detection
or re-PIN-entry — only an explicit Back / reset clears it.

## PIN handling

The `Pin` wrapper in `src/pin.ts` is single-use:

- `consume()` returns the value once, then clears the internal slot.
  Throws on second call.
- `toString` / `toJSON` / `valueOf` / `Symbol.toPrimitive` all return
  `"[REDACTED]"` so a stray `${pin}` or `console.log(pin)` prints garbage,
  not the digits.
- `scripts/check-no-pin-leak.sh` greps the source for `console.*` calls
  taking a `pin` reference and template literals interpolating one. Wired
  into `pnpm lint`.

**Attempt budget.** Taiwan Citizen Card locks after three wrong PIN
attempts. The setup screen tracks `attemptsRemaining` and surfaces the
remaining count in the panel body after each rejection. At 0 attempts the
input and Verify button are disabled and the body explains the card is
locked. The implementation is in `src/screens/setup.ts::paintPin` and
`refreshPinControls`.

## Cancellation

Each proving run owns an `AbortController` in `src/main.ts`. Leaving the
`proving` phase aborts the controller (cancels in-flight HiPKI /
verifier requests via `AbortSignal`; the SMT step is now a synchronous
Worker RPC so there's nothing to cancel mid-flight) and terminates the
Worker. A fresh Worker is spawned for the next run.

The replace-the-worker approach avoids tagging every Worker → main
message with a runId for stale-event filtering. The Worker init cost
(reload wasm + thread pool) is small relative to the proving step.

`src/pipeline.ts::PipelineAborted` is the sentinel thrown when the signal
fires; `main.ts` swallows it without dispatching a duplicate FSM error.

The verifier client (`src/verifier-client.ts`) composes the caller's
`AbortSignal` with an `AbortSignal.timeout(...)` so a hung upstream can't
leave the UI spinning forever. Default 15s, override via
`VITE_VERIFIER_TIMEOUT_MS`. `src/smt-client.ts` no longer issues network
requests — proof queries are Worker RPCs that resolve in microseconds
against the already-loaded local tree.

The HiPKI popup is user-driven and not directly cancellable from the main
thread; it has its own internal timeout (`hipki-popup.ts`,
`READY_TIMEOUT_MS` / `RESPONSE_TIMEOUT_MS`).

## The drift guard

The TS app does not re-implement input building. It calls
`build_cert_chain_input` / `build_device_sig_input` from
`spartan2-wasm/pkg/`, which are wasm-bindgen wrappers over the shared
`zkid-input-builder` Rust crate. The same crate is used by the native
CLI in `ecdsa-spartan2`.

`spartan2-wasm/tests/input_builder_drift.rs` loads the bundled
`pkcs11info_test.json` + `response_sign_test.json`, runs the wasm crate's
native-test entry points, and byte-compares against the reference
`circom/inputs/{cert_chain_rs2048,device_sig_rs2048}/input.json` produced
by `cargo run -- generate-split-input`. CI blocks the PR if a single byte
diverges.

This is the load-bearing guarantee for in-browser proving: a one-byte
disagreement between the wasm builder and the Rust CLI reference is
exactly the class of failure that produces `Too many values for input
signal __placeholder__` (PR #40 root cause).

## Revocation proof (local-first)

Revocation is verified by a Sparse Merkle Tree non-membership proof over
the user's certificate serial. The original design hit a REST endpoint
(`GET /proof/{issuer}/{serial}`) on `moica-revocation-smt`. That leaked
the serial to a third party on every proof attempt — a direct contradiction
of the "privacy-preserving identity verification" premise. The web prover
now rebuilds the tree in-browser.

**Assets.** `moica-revocation-smt` release `snapshot-latest` publishes:

- `smt.wasm` — Go SMT engine, ~3.5 MB, Poseidon-P256 (same hash the
  zkID cert-chain circuit consumes — zero hash-compat risk).
- `wasm_exec.js` — Go's JS runtime shim (~17 KB).
- `g2-tree-snapshot.bin.gz`, `g3-tree-snapshot.bin.gz` — per-issuer tree
  state in the binary format defined by
  [moica-revocation-smt PR #22](https://github.com/moven0831/moica-revocation-smt/pull/22).
  ~73 MB gzipped for G2, ~21 MB for G3.

**Binary layout** (BigEndian):

```
Header (52 bytes):
  [0:2]   magic       u16  0x534D ("SM")
  [2:4]   version     u16  1
  [4:8]   nodeCount   u32
  [8:40]  rootHash    [32]byte
  [40:44] depth       u32  (always 128 for zkID)
  [44:52] crlNumber   u64

Per node:
  [0:1]   type        u8   0=branch, 1=leaf
  [1:33]  hash        [32]byte
  Branch: [33:65] left, [65:97] right        (97 bytes)
  Leaf:   [33:65] key, [65:97] value,
          [97:129] entryMark                 (129 bytes)
```

**Flow.**

1. Setup entry kicks off the proving runtime warmup (PKs + witnesscalc).
   This is issuer-independent and runs in the Worker.
2. User reads their card via HiPKI. `$hipki` reaches `card_ready` with
   the issuer derived from the subject DN.
3. `main.ts` posts `{type:"load_smt", issuer}` to the Worker. The Worker
   downloads `smt.wasm` + `wasm_exec.js` + the per-issuer snapshot via
   the same `ensureAsset` pipeline used for PKs (OPFS cache + gzip
   decompress + SHA-256 verify when `snapshot-manifest.json` is present).
4. The Worker instantiates the Go runtime, calls `smtInitTree`, streams
   the snapshot in 10,000-node chunks via `smtAddNodeChunk` (yielding to
   the event loop between batches so cancel messages can land), then
   calls `smtFinalize`.
5. The panel flips to `ready`; `$setupReady` now requires all four
   panels green (warmup, card, revocation, PIN) before Continue enables.
6. During proving, the `smt` step is a Worker RPC: `main.ts` posts
   `{type:"smt_proof", requestId, serialHex}`, the Worker calls
   `smtCreateProof` against the loaded tree, converts the response to
   the circuit-input shape via `convertSmtProofToCircuitInputs`, and
   replies with `{step:"smt_proof_done", requestId, inputs}`.

**Trust model.** The app trusts the GitHub Release blob (PKs and SMT
snapshot alike). On-chain cross-verification of the snapshot root against
the Arbitrum Sepolia `SMTRootStorage` contract would tighten this further
and is tracked as a follow-up — it needs an RPC endpoint + ethers.js and
isn't load-bearing for the current demo.

**Test escape hatch.** `globalThis.__SMT_TEST_PROOF__` on the main thread
(seeded by Playwright via `page.addInitScript`) short-circuits both
`load_smt` and the proof RPC. Worker globals are isolated so the hook
can't live in the Worker; keeping it on the main thread avoids bundling
Go `smt.wasm` or a fake tree into the e2e harness.

## Asset cache

PKs and witness-wasm bundles live behind OPFS via `src/asset-store.ts`.
First load downloads from `VITE_PK_BASE_URL` (defaults to the GitHub
Release tagged `latest`), validates SHA-256 against the manifest, and
writes to OPFS. Subsequent loads hit the cache.

The setup screen kicks off the download eagerly on mount so by the time
the user has clicked through HiPKI + PIN the assets are usually ready
and Continue is unblocked immediately.

## Test coverage

- `pnpm test` (vitest) — unit tests for clients, store transitions, Pin,
  bytes utilities, asset-download, witness wrapper.
- `pnpm test:e2e` (Playwright, mocked) — end-to-end with mocked HiPKI
  popup + verifier + SMT. Includes wrong-PIN-twice → final-gate flow,
  verifier-down → error + Retry path.
- `pnpm test:e2e:real` (Playwright, real) — runs only with
  `E2E_MODE=real` + `E2E_PIN=...` against a live HiPKI LocalSignServer +
  moica-revocation-smt + go-zkid-verifier. Tagged `@real` so the default
  CI skips it.
- `pnpm lint` — `tsc --noEmit` plus `scripts/check-no-pin-leak.sh`.

## Files of interest

- `src/main.ts` — boot, FSM listener, AbortController + Worker lifecycle.
- `src/router.ts` — phase → screen mounting.
- `src/store.ts` — discriminated-union FSM and reducer.
- `src/setup-state.ts` — HipkiState + PinState atoms.
- `src/screens/{landing,setup,proving}.ts` — screen renderers.
- `src/hipki-popup.ts` — popupForm postMessage bridge.
- `src/hipki-client.ts` — typed HiPKI surface; delegates to the popup.
- `src/smt-client.ts` — main-thread wrapper that RPCs the Worker's SMT engine.
- `src/smt-local.ts` — Worker-side Go SMT engine + streaming snapshot loader.
- `src/smt-snapshot.ts` — binary-format parser for the PR #22 snapshot layout.
- `src/verifier-client.ts` — go-zkid-verifier client with timeout.
- `src/pipeline.ts` — main-thread orchestrator (challenge → sign → smt →
  build → Worker handoff).
- `src/inputs.ts` — TS wrapper around the wasm input-builder exports.
- `src/worker.ts` — CPU/wasm side of the pipeline.
- `src/pin.ts` — single-use redacting PIN wrapper.
- `vite.config.ts` — COOP / COEP and dev-server config.
