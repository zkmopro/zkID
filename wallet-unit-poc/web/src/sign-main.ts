// Entry point for `/` (sign route). Runs landing → setup → ready, drives
// HiPKI + SMT via a Worker, then on Start-proving runs the sign-phase
// pipeline (challenge → sign → smt → build) and hands off `ProveInput` to
// `/prove` via sessionStorage.
//
// Kept separate from `prove-main.ts` because `/` and `/prove` are served
// with different COOP headers (see `vite.config.ts`): `/` preserves
// `window.opener` for the HiPKI popup; `/prove` runs in a cross-origin-
// isolated context so `wasm-bindgen-rayon` can use SharedArrayBuffer.

import "./style.css";
import { $challenge, clearChallenge } from "./challenge-state";
import { runSignPhasePipeline, PipelineAborted } from "./pipeline";
import { mountRouter } from "./router";
import {
  $hipki,
  $pin,
  $smt,
  $warmup,
  resetSetup,
} from "./setup-state";
import { getSmtTestProof } from "./smt-client";
import { saveProveInput } from "./storage-handoff";
import { dispatch, $state, type AppState } from "./store";
type Phase = AppState["phase"];
import { resetUi, result } from "./ui";
import { createWorkerLifecycle } from "./worker-lifecycle";
import type { WorkerInMsg } from "./worker";

function boot(): void {
  const root = document.querySelector<HTMLElement>("#app");
  if (!root) {
    throw new Error("sign-main.ts: #app root missing in index.html");
  }

  mountRouter(root);

  const { ensureWorker, terminateWorker } = createWorkerLifecycle();
  let runController: AbortController | null = null;

  function abortActiveRun(): void {
    runController?.abort();
    runController = null;
  }

  function killWorkerForCancel(): void {
    terminateWorker();
    $warmup.set({ status: "idle" });
    $smt.set({ status: "idle" });
  }

  async function handleSignPhase(): Promise<void> {
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
      const proveInput = await runSignPhasePipeline(ensureWorker(), {
        card: hipkiState.card,
        pin: pinState.pin,
        nullifier: `zkid-${hipkiState.card.serialHex}`,
        challenge: challengeState.challenge,
        signal: myController.signal,
      });
      // The Worker is about to be torn down by the page navigation; drop
      // the refs here first so no late message can fire into a disposed FSM.
      terminateWorker();
      saveProveInput(proveInput);
      window.location.assign("/prove");
    } catch (err) {
      if (err instanceof PipelineAborted) return;
      if ($state.get().phase === "proving") {
        const message = err instanceof Error ? err.message : String(err);
        dispatch({ type: "pipeline_error", where: "proving", message });
      }
    } finally {
      if (runController === myController) runController = null;
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

  $warmup.listen((warmup) => {
    if (warmup.status !== "idle") return;
    if ($state.get().phase !== "setup") return;
    triggerWarmupIfIdle();
  });

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

  let prevPhase: Phase = $state.get().phase;
  $state.listen(async (state) => {
    const cameFrom = prevPhase;
    const wasProving = cameFrom === "proving";
    prevPhase = state.phase;

    if (state.phase !== "proving") abortActiveRun();

    switch (state.phase) {
      case "landing":
        resetSetup();
        clearChallenge();
        terminateWorker();
        $warmup.set({ status: "idle" });
        return;
      case "setup":
        // Cancel mid-proving lands here. Kill the warm Worker and reset
        // $pin so the user must re-verify before the next attempt.
        if (wasProving) {
          killWorkerForCancel();
          $pin.set({ status: "pending" });
        }
        clearChallenge();
        triggerWarmupIfIdle();
        return;
      case "ready":
        return;
      case "proving":
        await handleSignPhase();
        return;
      // review / submitting / result / error can only be reached on /prove;
      // if the FSM somehow lands here on /, fall through to no-op so the
      // existing error screen still renders.
      case "review":
      case "submitting":
      case "result":
      case "error":
        return;
    }
  });
}

boot();
