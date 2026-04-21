// Entry point for `/prove` (proving route). Picks up a `ProveInput` handed
// over from `/` via sessionStorage, runs a fresh Worker in a cross-origin-
// isolated document so `wasm-bindgen-rayon` can spawn a real thread pool,
// then drives proving → review → submitting → result.
//
// If no stored input exists (e.g., user navigates directly to /prove, or
// refreshes mid-proving), redirect back to `/` rather than render an
// empty page.

import "./style.css";
import { markPriorStepsDone } from "./progress";
import { mountRouter } from "./router";
import { clearProveInput, consumeProveInput } from "./storage-handoff";
import { dispatch, $state, type AppState } from "./store";
import { resetUi, result } from "./ui";
import { submitLinkVerify } from "./verifier-client";
import { createWorkerLifecycle } from "./worker-lifecycle";
import type { Progress, WorkerInMsg } from "./worker";

function boot(): void {
  const root = document.querySelector<HTMLElement>("#app");
  if (!root) {
    throw new Error("prove-main.ts: #app root missing in prove.html");
  }

  const proveInput = consumeProveInput();
  if (!proveInput) {
    // No handoff — someone navigated to /prove directly or refreshed
    // mid-proving. Bounce back to / for a clean restart.
    clearProveInput();
    window.location.replace("/");
    return;
  }

  // Bootstrap state before anything subscribes to $state so the first
  // render paints the proving screen, not a flash of landing. This
  // deliberately bypasses the store's `start_proving` transition because
  // /prove enters proving directly from a stored handoff — see the note
  // in store.ts on the `landing → proving` direct bootstrap.
  //
  // Mark sign-phase steps (challenge/sign/smt/build) done BEFORE first
  // render — they completed on / and the user just saw green checks for
  // them. Deferring this until `warmup_done` leaves them gray for the
  // multi-second warmup and looks like their prior work was lost.
  resetUi();
  markPriorStepsDone("prove_cert");
  result.set({ kind: "running" });
  $state.set({ phase: "proving", startedAt: performance.now() });

  let submitController: AbortController | null = null;
  let postedProve = false;
  let disposeRouter: (() => void) | null = null;
  let redirected = false;

  const { ensureWorker, terminateWorker } = createWorkerLifecycle({
    onProgress: (data, w) => {
      if (data.step === "warmup_done" && !postedProve) {
        postedProve = true;
        const msg: WorkerInMsg = { type: "prove", input: proveInput };
        w.postMessage(msg);
        return;
      }
      if (data.step === "proving_complete") {
        logProvingComplete(data);
      }
    },
  });

  function cancelActiveSubmit(): void {
    submitController?.abort();
    submitController = null;
  }

  // retry_proving and reset_to_setup land on `setup` (and `reset` on
  // `landing`). /prove has no sign-phase screens — redirect guard makes
  // this idempotent so a second transition during teardown is a no-op.
  function sendUserBackToSign(): void {
    if (redirected) return;
    redirected = true;
    disposeRouter?.();
    disposeRouter = null;
    terminateWorker();
    clearProveInput();
    window.location.replace("/");
  }

  // Listener runs before mountRouter's subscription, so a transition to
  // setup/landing is intercepted before the router paints those screens.
  $state.listen(async (state) => {
    if (redirected) return;
    if (state.phase !== "submitting") cancelActiveSubmit();

    switch (state.phase) {
      case "proving":
      case "review":
        // Worker stays alive across review — user may click Retry or the
        // final submit, and tearing the pool down between prove and submit
        // is pure waste.
        return;
      case "submitting":
        await handleSubmittingPhase(state);
        return;
      case "result":
        terminateWorker();
        return;
      case "setup":
      case "landing":
        sendUserBackToSign();
        return;
      case "error":
        terminateWorker();
        return;
    }
  });

  disposeRouter = mountRouter(root);

  async function handleSubmittingPhase(
    state: Extract<AppState, { phase: "submitting" }>,
  ): Promise<void> {
    cancelActiveSubmit();
    submitController = new AbortController();
    const mine = submitController;
    const t0 = performance.now();
    try {
      const res = await submitLinkVerify(
        {
          challengeId: state.run.challengeId,
          certChainType: state.run.certChainType,
          certChainProofBytes: state.run.certProofBytes,
          deviceSigProofBytes: state.run.deviceProofBytes,
          nullifier: state.run.nullifier,
        },
        { signal: mine.signal },
      );
      const submitMs = performance.now() - t0;
      dispatch({ type: "submit_complete", verified: res.verified, submitMs });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const message = err instanceof Error ? err.message : String(err);
      dispatch({ type: "pipeline_error", where: "submit", message });
    } finally {
      if (submitController === mine) submitController = null;
    }
  }

  const warmupMsg: WorkerInMsg = { type: "warmup" };
  ensureWorker().postMessage(warmupMsg);
}

// Measurement harness: one line per complete run, carrying the per-circuit
// breakdown + whether the rayon pool actually ran. Lets before/after
// threaded-vs-single-threaded comparisons land in console logs without a
// profiler.
function logProvingComplete(
  data: Extract<Progress, { step: "proving_complete" }>,
): void {
  console.info("[zkid] proving_complete", {
    crossOriginIsolated: globalThis.crossOriginIsolated,
    hardwareConcurrency: navigator.hardwareConcurrency,
    threads: data.threads,
    provingMs: Math.round(data.provingMs),
    certWitnessMs: Math.round(data.certWitnessMs),
    certProveMs: Math.round(data.certProveMs),
    deviceWitnessMs: Math.round(data.deviceWitnessMs),
    deviceProveMs: Math.round(data.deviceProveMs),
  });
}

boot();
