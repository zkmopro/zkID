// Translates Worker Progress events into `ui.ts` step-atom + result-atom
// updates and dispatches FSM terminal events on `done` / `error`.

import { humanBytes } from "./format";
import { dispatch } from "./store";
import { result, STEP_ORDER, steps, type Step, type StepStatus } from "./ui";
import type { Progress } from "./worker";

function downloadLabel(p: Extract<Progress, { step: "download" }>): string {
  if (!p.asset) return "";
  const done = humanBytes(p.bytesDone);
  const total = humanBytes(p.bytesTotal);
  if (done && total) return `${p.asset} — ${done} / ${total}`;
  if (done) return `${p.asset} — ${done}`;
  return p.asset;
}

function markPrior(step: Step, status: StepStatus): void {
  for (const s of STEP_ORDER) {
    if (s === step) return;
    const cur = steps[s].get();
    if (cur.status === "pending" || cur.status === "in_progress") {
      steps[s].set({ ...cur, status });
    }
  }
}

export function applyProgress(p: Progress): void {
  switch (p.step) {
    case "preflight":
    case "download":
    case "load":
    case "witness":
    case "prove":
    case "submit": {
      const stepKey = p.step;
      const atomRef = steps[stepKey];
      let label = "";
      if (p.step === "download") label = downloadLabel(p);
      else if (
        (p.step === "load" || p.step === "witness" || p.step === "prove") &&
        "kind" in p &&
        p.kind
      ) {
        label = p.step === "prove" && p.phase ? `${p.kind} (${p.phase})` : p.kind;
      }
      if (p.status === "in_progress") {
        markPrior(stepKey, "done");
        atomRef.set({ status: "in_progress", label });
      } else {
        atomRef.set({ status: "done", label });
      }
      return;
    }
    case "done": {
      for (const s of STEP_ORDER) {
        const cur = steps[s].get();
        if (cur.status !== "error") {
          steps[s].set({ ...cur, status: "done" });
        }
      }
      result.set({
        kind: "done",
        verified: p.verified,
        durationMs: p.durationMs,
      });
      dispatch({
        type: "proving_done",
        verified: p.verified,
        durationMs: p.durationMs,
      });
      return;
    }
    case "error": {
      let target: Step | undefined;
      for (const s of STEP_ORDER) {
        if (steps[s].get().status === "in_progress") {
          target = s;
          break;
        }
      }
      if (!target) {
        for (const s of STEP_ORDER) {
          if (steps[s].get().status === "pending") {
            target = s;
            break;
          }
        }
      }
      if (target) {
        steps[target].set({ status: "error", error: p.message });
      }
      result.set({ kind: "error", message: `${p.where}: ${p.message}` });
      dispatch({
        type: "pipeline_error",
        where: p.where,
        message: p.message,
      });
      return;
    }
  }
}
