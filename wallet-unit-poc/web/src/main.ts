// Entry point. Boots the router, owns the Worker lifecycle, and drives the
// phase-specific orchestration (warmup on setup, prove on proving, submit
// on submitting, teardown on landing).
//
// Cancellation: each proving run owns an AbortController that is aborted on
// any transition out of `proving`. Because `prove()` is blocking wasm, real
// mid-flight cancellation terminates the Worker, which discards the warm PK
// state — the user lands back on setup with the Assets panel showing
// "not warmed" so they explicitly re-warm before retrying.

import "./style.css";
import { $challenge, clearChallenge } from "./challenge-state";
import { runProvingPipeline, PipelineAborted } from "./pipeline";
import { applyProgress } from "./progress";
import { mountRouter } from "./router";
import {
  $hipki,
  $pin,
  $smt,
  $warmup,
  resetSetup,
} from "./setup-state";
import { getSmtTestProof } from "./smt-client";
import { dispatch, $state, type AppState } from "./store";
type Phase = AppState["phase"];
import { resetUi, result } from "./ui";
import { submitLinkVerify } from "./verifier-client";
import type { Progress, WorkerInMsg } from "./worker";

function boot(): void {
  const root = document.querySelector<HTMLElement>("#app");
  if (!root) {
    throw new Error("main.ts: #app root missing in index.html");
  }

  mountRouter(root);

  let worker: Worker | null = null;
  let runController: AbortController | null = null;
  let submitController: AbortController | null = null;

  function spawnWorker(): Worker {
    const w = new Worker(new URL("./worker.ts", import.meta.url), {
      type: "module",
    });
    w.onmessage = (ev: MessageEvent<Progress>) => applyProgress(ev.data);
    w.onerror = (ev) => {
      const message = ev.message || "worker crashed";
      result.set({ kind: "error", message });
      dispatch({ type: "pipeline_error", where: "worker", message });
      console.error("worker error", ev);
    };
    return w;
  }

  function ensureWorker(): Worker {
    if (!worker) worker = spawnWorker();
    return worker;
  }

  function terminateWorker(): void {
    if (!worker) return;
    // Drop handlers before terminate() so any already-queued messages can't
    // reach the FSM after we've decided to tear the Worker down.
    worker.onmessage = null;
    worker.onerror = null;
    worker.terminate();
    worker = null;
  }

  function abortActiveRun(): void {
    runController?.abort();
    runController = null;
  }

  function killWorkerForCancel(): void {
    // `prove()` is blocking wasm with no other interrupt — the only way to
    // stop mid-proving is to terminate. Flip warmup and SMT back to idle so
    // the panels reflect that a fresh load is needed before the next run.
    terminateWorker();
    $warmup.set({ status: "idle" });
    $smt.set({ status: "idle" });
  }

  function cancelActiveSubmit(): void {
    submitController?.abort();
    submitController = null;
  }

  async function handleProvingPhase(): Promise<void> {
    resetUi();
    result.set({ kind: "running" });

    const hipkiState = $hipki.get();
    const pinState = $pin.get();
    const challengeState = $challenge.get();
    if (hipkiState.status !== "card_ready") {
      dispatch({
        type: "pipeline_error",
        where: "setup",
        message: "card not ready",
      });
      return;
    }
    if (pinState.status !== "locked") {
      dispatch({
        type: "pipeline_error",
        where: "setup",
        message: "PIN not verified",
      });
      return;
    }
    if ($warmup.get().status !== "ready") {
      dispatch({
        type: "pipeline_error",
        where: "setup",
        message: "proving runtime not warmed",
      });
      return;
    }
    if (challengeState.status !== "ready") {
      // Ready screen gates Start proving on a ready challenge; guard
      // anyway because a late fetch here would consume user-activation
      // and get the HiPKI popup blocked.
      dispatch({
        type: "pipeline_error",
        where: "challenge",
        message: "challenge not pre-fetched",
      });
      return;
    }

    runController = new AbortController();
    const myController = runController;
    try {
      await runProvingPipeline(ensureWorker(), {
        card: hipkiState.card,
        pin: pinState.pin,
        nullifier: `zkid-${hipkiState.card.serialHex}`,
        challenge: challengeState.challenge,
        signal: myController.signal,
      });
    } catch (err) {
      if (err instanceof PipelineAborted) return;
      // Throws inside `stage()` already dispatched `pipeline_error` via
      // fail(). Any throw before the first stage (e.g., encoding the TBS,
      // a missing Worker) would otherwise vanish — dispatch here so the
      // user sees an error screen instead of an infinite spinner.
      if ($state.get().phase === "proving") {
        const message = err instanceof Error ? err.message : String(err);
        dispatch({ type: "pipeline_error", where: "proving", message });
      }
    } finally {
      if (runController === myController) runController = null;
    }
  }

  async function handleSubmittingPhase(state: Extract<AppState, { phase: "submitting" }>): Promise<void> {
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
      dispatch({
        type: "submit_complete",
        verified: res.verified,
        submitMs,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const message = err instanceof Error ? err.message : String(err);
      dispatch({ type: "pipeline_error", where: "submit", message });
    } finally {
      if (submitController === mine) submitController = null;
    }
  }

  function triggerWarmupIfIdle(): void {
    if ($warmup.get().status === "idle") {
      const w = ensureWorker();
      const msg: WorkerInMsg = { type: "warmup" };
      w.postMessage(msg);
    }
  }

  // Triggered by HiPKI reaching `card_ready`: the Worker now knows the
  // issuer and can download/ingest the per-issuer SMT snapshot. Separate
  // from warmup because warmup fires on setup entry (before any card is
  // read) and loading both g2 and g3 snapshots would waste ~94 MB of
  // bandwidth on a card the user isn't holding.
  function triggerLoadSmtForCard(): void {
    const hipki = $hipki.get();
    if (hipki.status !== "card_ready") return;
    const smt = $smt.get();
    if (smt.status === "running") return;
    if (smt.status === "ready" && smt.issuer === hipki.card.issuer) return;
    // Playwright / vitest escape hatch: when a fixture proof is seeded on
    // the page global, skip the Worker round-trip entirely and flip the
    // panel to ready synchronously. Worker globals are isolated so the
    // hook can't propagate automatically.
    if (getSmtTestProof()) {
      $smt.set({
        status: "ready",
        issuer: hipki.card.issuer,
        rootHex: "test",
        crlNumber: "0",
      });
      return;
    }
    const w = ensureWorker();
    const msg: WorkerInMsg = { type: "load_smt", issuer: hipki.card.issuer };
    w.postMessage(msg);
  }

  // The Assets panel flips `$warmup` back to `idle` on Retry/Re-download.
  // Re-kick warmup here so the screen doesn't need direct Worker access.
  $warmup.listen((warmup) => {
    if (warmup.status !== "idle") return;
    if ($state.get().phase !== "setup") return;
    triggerWarmupIfIdle();
  });

  // Two listeners both feed `triggerLoadSmtForCard`, guarded by its running/
  // ready short-circuit so they never double-post:
  //   - $hipki → card_ready: first time the issuer is known, start the load.
  //   - $smt → idle: user clicked Retry/Re-download on the Revocation panel;
  //     the screen can't reach the Worker directly, so it just flips the atom.
  $hipki.listen((hipki) => {
    if (hipki.status !== "card_ready") return;
    if ($state.get().phase !== "setup") return;
    triggerLoadSmtForCard();
  });
  $smt.listen((smt) => {
    if (smt.status !== "idle") return;
    if ($state.get().phase !== "setup") return;
    triggerLoadSmtForCard();
  });

  // Phases where the session Pin may have been consumed (sign step ran).
  // Transitioning back to setup from any of these requires a fresh Verify
  // before the next proving run.
  const PIN_CONSUMED_PHASES: ReadonlySet<Phase> = new Set<Phase>([
    "proving",
    "review",
    "submitting",
    "result",
  ]);

  let prevPhase: Phase = $state.get().phase;
  $state.listen(async (state) => {
    const cameFrom = prevPhase;
    const wasProving = cameFrom === "proving";
    prevPhase = state.phase;

    // Abort active controllers on any transition out of their phase.
    if (state.phase !== "proving") abortActiveRun();
    if (state.phase !== "submitting") cancelActiveSubmit();

    switch (state.phase) {
      case "landing":
        // Full reset: drop setup atoms + pre-fetched challenge, terminate
        // the Worker so next session starts fresh.
        resetSetup();
        clearChallenge();
        terminateWorker();
        $warmup.set({ status: "idle" });
        return;
      case "setup":
        // Reaching setup from proving means the user cancelled mid-run.
        // Kill the warm Worker and drop any stale challenge so the next
        // Ready mount fetches a fresh one (single-use).
        if (wasProving) killWorkerForCancel();
        // Strict single-use Pin: drop $pin if we're arriving from a phase
        // where the session Pin may have been consumed. Forces re-verify
        // before the next proving run. Card + warmup stay green so the
        // user only re-enters the PIN, not everything else.
        if (PIN_CONSUMED_PHASES.has(cameFrom)) {
          $pin.set({ status: "pending" });
        }
        clearChallenge();
        triggerWarmupIfIdle();
        return;
      case "ready":
        return;
      case "review":
        // Challenge was consumed by this proving run (single-use); drop
        // it so any later retry re-enters Ready and fetches a fresh one.
        clearChallenge();
        return;
      case "proving":
        await handleProvingPhase();
        return;
      case "submitting":
        await handleSubmittingPhase(state);
        return;
      case "result":
      case "error":
        return;
    }
  });
}

boot();
