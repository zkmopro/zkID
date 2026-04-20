// Entry point for the zkID in-browser prover.
//
// Responsibilities:
//  1. Spawn the dedicated Worker (off-main-thread prover pipeline).
//  2. Mount the reactive step list + result banner via src/ui.ts.
//  3. On "Prove" click: load fixture inputs from /fixtures/, send { type: "run" }
//     to the Worker, and translate incoming Progress events into atom updates.
//
// The fixture flow is a stand-in for the real credential-picker UI; production
// wiring will replace fetchFixtures() with whatever surface pulls cert, device,
// and nullifier out of a wallet / card reader.

import "./style.css";
import type { Progress, RunInput, WorkerInMsg } from "./worker";
import {
  mountSteps,
  resetUi,
  result,
  steps,
  type Step,
  type StepStatus,
} from "./ui";

const STEPS_IN_ORDER: Step[] = [
  "preflight",
  "challenge",
  "download",
  "load",
  "witness",
  "prove",
  "submit",
];

function humanBytes(n: number | undefined): string {
  if (!n || !Number.isFinite(n) || n <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

function downloadLabel(p: Extract<Progress, { step: "download" }>): string {
  if (!p.asset) return "";
  const done = humanBytes(p.bytesDone);
  const total = humanBytes(p.bytesTotal);
  if (done && total) return `${p.asset} — ${done} / ${total}`;
  if (done) return `${p.asset} — ${done}`;
  return p.asset;
}

function markPrior(step: Step, status: StepStatus): void {
  // Mark any still-pending steps before `step` as `status` so the UI doesn't
  // leave earlier rows spinning forever when the Worker jumps ahead.
  for (const s of STEPS_IN_ORDER) {
    if (s === step) return;
    const cur = steps[s].get();
    if (cur.status === "pending" || cur.status === "in_progress") {
      steps[s].set({ ...cur, status });
    }
  }
}

function applyProgress(p: Progress): void {
  switch (p.step) {
    case "preflight":
    case "challenge":
    case "download":
    case "load":
    case "witness":
    case "prove":
    case "submit": {
      const stepKey = p.step;
      const atomRef = steps[stepKey];
      let label = "";
      if (p.step === "download") label = downloadLabel(p);
      else if (p.step === "challenge" && "challengeId" in p && p.challengeId)
        label = `challenge: ${p.challengeId}`;
      else if (
        (p.step === "load" ||
          p.step === "witness" ||
          p.step === "prove") &&
        "kind" in p &&
        p.kind
      ) {
        label = p.step === "prove" && p.phase ? `${p.kind} (${p.phase})` : p.kind;
      }
      // Once a step goes in_progress, older pending steps become "done"
      // implicitly — the pipeline is strictly sequential.
      if (p.status === "in_progress") {
        markPrior(stepKey, "done");
        atomRef.set({ status: "in_progress", label });
      } else {
        atomRef.set({ status: "done", label });
      }
      return;
    }
    case "done": {
      for (const s of STEPS_IN_ORDER) {
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
      return;
    }
    case "error": {
      // Mark the step currently in_progress (if any) as errored; otherwise the
      // first still-pending step — that's where the failure surfaced.
      let target: Step | undefined;
      for (const s of STEPS_IN_ORDER) {
        if (steps[s].get().status === "in_progress") {
          target = s;
          break;
        }
      }
      if (!target) {
        for (const s of STEPS_IN_ORDER) {
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
      return;
    }
  }
}

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

function renderShell(_root: HTMLElement): {
  button: HTMLButtonElement;
  list: HTMLOListElement;
  result: HTMLElement;
} {
  // index.html already paints the button / list / result shell. Bind to those
  // elements rather than re-creating them.
  const button = document.querySelector<HTMLButtonElement>(
    '[data-testid="prove-button"]',
  );
  const list = document.querySelector<HTMLOListElement>(
    '[data-testid="step-list"]',
  );
  const resultEl = document.querySelector<HTMLElement>("#result");
  if (!button || !list || !resultEl) {
    throw new Error("main.ts: required DOM nodes missing (prove button / step list / result)");
  }
  return { button, list, result: resultEl };
}

function main(): void {
  const root = document.querySelector<HTMLElement>("main");
  if (!root) {
    throw new Error("main.ts: <main> root missing in index.html");
  }
  const { button, list, result: resultEl } = renderShell(root);
  mountSteps(list, resultEl);

  const worker = new Worker(new URL("./worker.ts", import.meta.url), {
    type: "module",
  });
  worker.onmessage = (ev: MessageEvent<Progress>) => applyProgress(ev.data);
  worker.onerror = (ev) => {
    const message = ev.message || "worker crashed";
    result.set({ kind: "error", message });
    console.error("worker error", ev);
  };

  button.addEventListener("click", async () => {
    if (button.disabled) return;
    button.disabled = true;
    resetUi();
    result.set({ kind: "running" });

    let input: RunInput;
    try {
      input = await loadFixtureInputs();
    } catch (err) {
      // Fixtures failed to load — the Worker was never started, so no terminal
      // "done"/"error" message will arrive. Re-enable the button immediately
      // rather than listening for something that will never fire.
      const message = err instanceof Error ? err.message : String(err);
      result.set({ kind: "error", message: `fixtures: ${message}` });
      button.disabled = false;
      return;
    }

    const msg: WorkerInMsg = { type: "run", input };
    // Register the terminal-message listener first so a near-instant error post
    // cannot race the `postMessage` call below.
    const enableOnTerminal = (ev: MessageEvent<Progress>) => {
      if (ev.data.step === "done" || ev.data.step === "error") {
        button.disabled = false;
        worker.removeEventListener("message", enableOnTerminal);
      }
    };
    worker.addEventListener("message", enableOnTerminal);
    worker.postMessage(msg);
  });
}

main();
