// Shared Worker spawn/terminate + onerror wiring for the two entry points
// (`/` sign route, `/prove` proving route). Both routes expect the same
// failure plumbing (dispatch `pipeline_error`, paint `result` error) so
// the error handler is owned here and not re-declared per entry point.

import { applyProgress } from "./progress";
import { dispatch } from "./store";
import { result } from "./ui";
import type { Progress } from "./worker";

export interface WorkerLifecycle {
  ensureWorker: () => Worker;
  terminateWorker: () => void;
}

export interface WorkerLifecycleOpts {
  /** Called after `applyProgress` on every message. Used by `/prove` to
   *  post `prove` after `warmup_done` and to log telemetry on complete. */
  onProgress?: (p: Progress, worker: Worker) => void;
}

export function createWorkerLifecycle(
  opts: WorkerLifecycleOpts = {},
): WorkerLifecycle {
  let worker: Worker | null = null;

  function spawn(): Worker {
    const w = new Worker(new URL("./worker.ts", import.meta.url), {
      type: "module",
    });
    w.onmessage = (ev: MessageEvent<Progress>) => {
      applyProgress(ev.data);
      opts.onProgress?.(ev.data, w);
    };
    w.onerror = (ev) => {
      // Preserve filename:line:col + underlying stack so Sentry / Playwright
      // traces have something more actionable than "worker crashed".
      const loc = ev.filename ? ` at ${ev.filename}:${ev.lineno}:${ev.colno}` : "";
      const message = `${ev.message || "worker crashed"}${loc}`;
      result.set({ kind: "error", message });
      dispatch({ type: "pipeline_error", where: "worker", message });
      console.error("worker error", ev, ev.error);
    };
    // Structured-clone failures on postMessage fire onmessageerror, not
    // onerror. Without this handler, the main thread would silently drop
    // the message and leave the UI waiting forever.
    w.onmessageerror = (ev) => {
      const message = "worker posted a message that could not be deserialized";
      result.set({ kind: "error", message });
      dispatch({ type: "pipeline_error", where: "worker", message });
      console.error("worker messageerror", ev);
    };
    return w;
  }

  function ensureWorker(): Worker {
    if (!worker) worker = spawn();
    return worker;
  }

  // Drop handlers before terminate() so any already-queued messages can't
  // reach the FSM after teardown.
  function terminateWorker(): void {
    if (!worker) return;
    worker.onmessage = null;
    worker.onerror = null;
    worker.onmessageerror = null;
    worker.terminate();
    worker = null;
  }

  return { ensureWorker, terminateWorker };
}
