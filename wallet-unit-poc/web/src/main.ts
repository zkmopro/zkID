// Entry point. Boots the router, spawns the prover Worker, and bridges
// `phase = "proving"` to the real HiPKI + SMT + wasm-input-builder pipeline.

import "./style.css";
import { runProvingPipeline } from "./pipeline";
import { applyProgress } from "./progress";
import { mountRouter } from "./router";
import { $card, $pin, resetSetup } from "./setup-state";
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

  let currentRun = 0;
  $state.listen(async (state) => {
    if (state.phase === "landing") {
      // Dropping setup state on return-to-landing ensures the next pass
      // re-detects the card and re-verifies the PIN — we don't leak a stale
      // `Pin` across sessions.
      resetSetup();
      return;
    }
    if (state.phase !== "proving") return;

    const runId = ++currentRun;
    resetUi();
    result.set({ kind: "running" });

    const cardState = $card.get();
    const pinState = $pin.get();
    if (cardState.status !== "ok") {
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
      await runProvingPipeline(worker, {
        card: cardState.card,
        pin: pinState.pin,
        // Nullifier is opaque to the prover; Phase 5 will replace this with
        // a user-scoped identifier (deterministic hash of the card subject
        // is the likely candidate). For now a stable placeholder keeps the
        // verifier's duplicate-detection noise-free within one session.
        nullifier: `zkid-${cardState.card.serialHex}`,
      });
    } catch {
      // `runProvingPipeline` already dispatched `pipeline_error`; swallow
      // here so the listener doesn't surface a duplicate.
    }
    // Stale-run guard: if the user hit Retry while we were mid-run, the
    // next `$state.listen` invocation will increment `currentRun` and
    // start fresh. The completed run's proof is discarded.
    if (runId !== currentRun) return;
  });
}

boot();
