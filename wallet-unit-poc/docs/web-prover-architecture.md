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
                       │                  (HiPKI popup) (SMT)    (zkid-input-builder via wasm)
                       │
                       └── Worker:       preflight → download → load → witness → prove → submit
                                          (asset cache)        (PK)    (witnesscalc) (Spartan2) (verifier)
```

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

## Cross-Origin isolation tradeoff

`vite.config.ts` sets:

- `Cross-Origin-Opener-Policy: same-origin-allow-popups`
- `Cross-Origin-Embedder-Policy: require-corp`

We need `same-origin-allow-popups` to keep `window.opener` alive across
the cross-origin popup. The stricter `same-origin` value severs it.

The cost: `crossOriginIsolated === false` in this configuration, which
disables `SharedArrayBuffer`. `wasm-bindgen-rayon` needs SAB for its
thread pool, so the Worker falls back to single-threaded proving when
isolation is off. The fallback lives in `src/worker.ts::clampThreads`:
returns 1 when `crossOriginIsolated !== true`, otherwise proceeds with
the usual hardware-concurrency clamp.

The single-threaded path is meaningfully slower (proving is the dominant
step), but it works. Re-enabling SAB would require moving HiPKI behind a
proxy or out-of-process bridge so we can drop the popup and tighten COOP
back to `same-origin`. Out of scope here.

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
`proving` phase aborts the controller (cancels in-flight HiPKI / SMT /
verifier requests via `AbortSignal`) and terminates the Worker. A fresh
Worker is spawned for the next run.

The replace-the-worker approach avoids tagging every Worker → main
message with a runId for stale-event filtering. The Worker init cost
(reload wasm + thread pool) is small relative to the proving step.

`src/pipeline.ts::PipelineAborted` is the sentinel thrown when the signal
fires; `main.ts` swallows it without dispatching a duplicate FSM error.

Network clients (`src/verifier-client.ts`, `src/smt-client.ts`) compose
the caller's `AbortSignal` with an `AbortSignal.timeout(...)` so a hung
upstream can't leave the UI spinning forever. Defaults: 15s for the
verifier, 10s for the SMT server. Override via `VITE_VERIFIER_TIMEOUT_MS`
/ `VITE_SMT_TIMEOUT_MS`.

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
- `src/smt-client.ts` — moica-revocation-smt client with timeout.
- `src/verifier-client.ts` — go-zkid-verifier client with timeout.
- `src/pipeline.ts` — main-thread orchestrator (challenge → sign → smt →
  build → Worker handoff).
- `src/inputs.ts` — TS wrapper around the wasm input-builder exports.
- `src/worker.ts` — CPU/wasm side of the pipeline.
- `src/pin.ts` — single-use redacting PIN wrapper.
- `vite.config.ts` — COOP / COEP and dev-server config.
