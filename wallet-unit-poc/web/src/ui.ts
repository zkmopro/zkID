// Reactive step-indicator store + DOM renderer.
//
// Each of the seven pipeline steps (preflight → submit) owns a nanostores atom
// whose state the Worker drives via postMessage. `mountSteps` paints the atoms
// into a provided <ol> and a result banner, returning a dispose function that
// unsubscribes all listeners. `resetUi` flips every atom back to "pending" so
// a fresh Prove run starts from a clean slate.

import { atom, type WritableAtom } from "nanostores";

export type Step =
  | "preflight"
  | "challenge"
  | "sign"
  | "smt"
  | "build"
  | "download"
  | "load"
  | "witness"
  | "prove"
  | "submit";

export type StepStatus = "pending" | "in_progress" | "done" | "error";

export interface StepState {
  status: StepStatus;
  label?: string;
  error?: string;
}

export type StepAtom = WritableAtom<StepState>;

export const STEP_ORDER: Step[] = [
  "preflight",
  "challenge",
  "sign",
  "smt",
  "build",
  "download",
  "load",
  "witness",
  "prove",
  "submit",
];

const STEP_TITLES: Record<Step, string> = {
  preflight: "Preflight",
  challenge: "Fetch challenge",
  sign: "Sign with card",
  smt: "Fetch revocation proof",
  build: "Build circuit inputs",
  download: "Download assets",
  load: "Load proving keys",
  witness: "Calculate witnesses",
  prove: "Prove",
  submit: "Submit to verifier",
};

export const steps: Record<Step, StepAtom> = {
  preflight: atom<StepState>({ status: "pending" }),
  challenge: atom<StepState>({ status: "pending" }),
  sign: atom<StepState>({ status: "pending" }),
  smt: atom<StepState>({ status: "pending" }),
  build: atom<StepState>({ status: "pending" }),
  download: atom<StepState>({ status: "pending" }),
  load: atom<StepState>({ status: "pending" }),
  witness: atom<StepState>({ status: "pending" }),
  prove: atom<StepState>({ status: "pending" }),
  submit: atom<StepState>({ status: "pending" }),
};

export type ResultState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "done"; verified: boolean; durationMs: number }
  | { kind: "error"; message: string };

export const result = atom<ResultState>({ kind: "idle" });

function stepRowMarkup(step: Step): string {
  const title = STEP_TITLES[step];
  return (
    `<li class="step" data-testid="step-${step}" data-status="pending">` +
    `<span class="step-icon" aria-hidden="true"></span>` +
    `<span class="step-title">${title}</span>` +
    `<span class="step-label" data-testid="step-${step}-label"></span>` +
    `</li>`
  );
}

function paintStepRow(li: HTMLElement, state: StepState): void {
  li.dataset.status = state.status;
  const label = li.querySelector<HTMLElement>(".step-label");
  if (label) {
    if (state.status === "error" && state.error) {
      label.textContent = state.error;
    } else {
      label.textContent = state.label ?? "";
    }
  }
}

function paintResult(el: HTMLElement, state: ResultState): void {
  el.dataset.kind = state.kind;
  el.textContent = "";
  if (state.kind === "idle") return;

  if (state.kind === "running") {
    const span = document.createElement("span");
    span.className = "result-line";
    span.textContent = "Proving…";
    el.appendChild(span);
    return;
  }

  if (state.kind === "done") {
    const badge = state.verified ? "verified" : "not verified";
    const line1 = document.createElement("div");
    line1.className = "result-line";
    line1.dataset.testid = "step-done";
    line1.textContent = `Done in ${state.durationMs.toFixed(0)} ms`;
    const line2 = document.createElement("div");
    line2.className = "result-line";
    line2.dataset.testid = "server-result";
    line2.textContent = `Server result: ${badge} (verified=${state.verified})`;
    el.append(line1, line2);
    return;
  }

  // Error path. `state.message` carries upstream text (HiPKI / verifier
  // error bodies); use textContent so an injected `<script>` can't reach
  // the DOM as markup.
  const head = document.createElement("div");
  head.className = "result-line";
  head.dataset.testid = "step-error";
  head.textContent = "Error";
  const body = document.createElement("div");
  body.className = "result-line";
  body.textContent = state.message;
  el.append(head, body);
}

/** Render the step list + result banner. Returns a dispose() that detaches
 *  every atom subscription so callers can tear down without leaks. */
export function mountSteps(
  listEl: HTMLOListElement,
  resultEl: HTMLElement,
): () => void {
  listEl.innerHTML = STEP_ORDER.map(stepRowMarkup).join("");
  resultEl.dataset.kind = "idle";
  resultEl.innerHTML = "";

  const disposers: Array<() => void> = [];
  for (const step of STEP_ORDER) {
    const li = listEl.querySelector<HTMLElement>(`[data-testid="step-${step}"]`);
    if (!li) continue;
    const unsub = steps[step].listen((s) => paintStepRow(li, s));
    paintStepRow(li, steps[step].get());
    disposers.push(unsub);
  }
  const unsubResult = result.listen((r) => paintResult(resultEl, r));
  paintResult(resultEl, result.get());
  disposers.push(unsubResult);

  return () => {
    for (const d of disposers) d();
  };
}

/** Reset every step atom back to "pending" and the result to "idle". */
export function resetUi(): void {
  for (const step of STEP_ORDER) {
    steps[step].set({ status: "pending" });
  }
  result.set({ kind: "idle" });
}
