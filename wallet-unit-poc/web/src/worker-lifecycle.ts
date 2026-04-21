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
      const message = ev.message || "worker crashed";
      result.set({ kind: "error", message });
      dispatch({ type: "pipeline_error", where: "worker", message });
      console.error("worker error", ev);
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
    worker.terminate();
    worker = null;
  }

  return { ensureWorker, terminateWorker };
}
