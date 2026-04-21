// Entry point. Boots the router, owns the Worker lifecycle, and bridges
// `phase = "proving"` to the real HiPKI + SMT + wasm-input-builder pipeline.
//
// Cancellation: each proving run owns an AbortController. Leaving the
// `proving` phase aborts the controller (cancels in-flight network calls)
// and terminates the Worker (stops CPU/wasm work mid-step), then a fresh
// Worker is spawned for the next run. The replace-the-worker approach
// avoids a runId-tagging dance in every Worker → main message and keeps
// stale `done`/`error` events from racing a new run's UI.

import "./style.css";
import { runProvingPipeline } from "./pipeline";
import { applyProgress } from "./progress";
import { mountRouter } from "./router";
import { $hipki, $pin, resetSetup } from "./setup-state";
import { dispatch, $state } from "./store";
import { resetUi, result } from "./ui";
import type { Progress } from "./worker";

function boot(): void {
  const root = document.querySelector<HTMLElement>("#app");
  if (!root) {
    throw new Error("main.ts: #app root missing in index.html");
  }

  mountRouter(root);

  let worker = spawnWorker();
  let runController: AbortController | null = null;

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

  function cancelActiveRun(): void {
    if (!runController) return;
    runController.abort();
    runController = null;
    worker.terminate();
    worker = spawnWorker();
  }

  $state.listen(async (state) => {
    // Any transition out of `proving` while a run is alive aborts it.
    // This covers Retry (proving → error → reset → landing) as well as
    // Back navigation in the proving screen once a Cancel button lands.
    if (state.phase !== "proving") cancelActiveRun();

    if (state.phase === "landing") {
      // Dropping setup state on return-to-landing ensures the next pass
      // re-detects the card and re-verifies the PIN — we don't leak a stale
      // `Pin` across sessions.
      resetSetup();
      return;
    }
    if (state.phase !== "proving") return;

    resetUi();
    result.set({ kind: "running" });

    const hipkiState = $hipki.get();
    const pinState = $pin.get();
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

    runController = new AbortController();
    const myController = runController;
    try {
      await runProvingPipeline(worker, {
        card: hipkiState.card,
        pin: pinState.pin,
        nullifier: `zkid-${hipkiState.card.serialHex}`,
        signal: myController.signal,
      });
    } catch {
      // `runProvingPipeline` already dispatched `pipeline_error` on real
      // failures and threw `PipelineAborted` on cancellation. Either way
      // the listener doesn't need to surface a duplicate here.
    } finally {
      if (runController === myController) runController = null;
    }
  });
}

boot();
