// Entry point. Boots the router, spawns the prover Worker, and bridges FSM
// `proving` phases to fixture loads + Worker postMessage. Phase 4 swaps the
// fixture load for a real HiPKI + SMT + wasm-input-builder pipeline; the
// FSM handshake stays the same.

import "./style.css";
import { applyProgress } from "./progress";
import { mountRouter } from "./router";
import { dispatch, $state } from "./store";
import { resetUi, result } from "./ui";
import type { Progress, RunInput, WorkerInMsg } from "./worker";

async function fetchFixture(path: string): Promise<Response> {
  const r = await fetch(path);
  if (!r.ok) {
    throw new Error(`fetch ${path} returned ${r.status} ${r.statusText}`);
  }
  return r;
}

async function loadFixtureInputs(): Promise<RunInput> {
  const [certRes, deviceRes, nullifierRes] = await Promise.all([
    fetchFixture("/fixtures/cert_chain_rs2048_input.json"),
    fetchFixture("/fixtures/device_sig_rs2048_input.json"),
    fetchFixture("/fixtures/nullifier.txt"),
  ]);
  const cert = (await certRes.json()) as Record<string, unknown>;
  const device = (await deviceRes.json()) as Record<string, unknown>;
  const nullifier = (await nullifierRes.text()).trim();
  return { cert, device, nullifier };
}

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

  // Guards "user hit Retry while fixtures load": any resolution of the in-flight
  // fixture promise races with a newer run, so a stale resolution must skip.
  let currentRun = 0;
  $state.listen(async (state) => {
    if (state.phase !== "proving") return;
    const runId = ++currentRun;
    resetUi();
    result.set({ kind: "running" });
    let input: RunInput;
    try {
      input = await loadFixtureInputs();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      dispatch({ type: "pipeline_error", where: "fixtures", message });
      return;
    }
    if (runId !== currentRun || $state.get().phase !== "proving") return;
    const msg: WorkerInMsg = { type: "run", input };
    worker.postMessage(msg);
  });
}

boot();
