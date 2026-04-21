// Entry point. Boots the router, spawns the prover Worker, and bridges
// `phase = "proving"` to the real HiPKI + SMT + wasm-input-builder pipeline.

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

  const worker = new Worker(new URL("./worker.ts", import.meta.url), {
    type: "module",
  });
  worker.onmessage = (ev: MessageEvent<Progress>) => applyProgress(ev.data);
  worker.onerror = (ev) => {
    const message = ev.message || "worker crashed";
    result.set({ kind: "error", message });
    dispatch({ type: "pipeline_error", where: "worker", message });
    console.error("worker error", ev);
  };

  $state.listen(async (state) => {
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

    try {
      // No cancellation today: if the user hits Retry mid-run, the in-flight
      // proof completes and posts its `done`/`error` to the FSM, racing the
      // new run. Phase 5 introduces an AbortController threaded into
      // `runProvingPipeline` so Retry can cancel cleanly.
      await runProvingPipeline(worker, {
        card: hipkiState.card,
        pin: pinState.pin,
        nullifier: `zkid-${hipkiState.card.serialHex}`,
      });
    } catch {
      // `runProvingPipeline` already dispatched `pipeline_error`; swallow
      // here so the listener doesn't surface a duplicate.
    }
  });
}

boot();
