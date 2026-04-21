// Result screen: covers both the terminal `result` phase (verified / not
// verified) and the `error` phase so users see a consistent outcome surface.

import { formatDuration } from "../format";
import { $state, dispatch } from "../store";

export function mountResult(root: HTMLElement): () => void {
  const state = $state.get();
  const isResult = state.phase === "result";
  const isError = state.phase === "error";

  let headline: string;
  let detail: string;
  let tone: "done" | "error" = "done";
  let testidBadge: string;

  if (isResult) {
    const total = state.provingMs + state.submitMs;
    if (state.verified) {
      headline = "Proof verified";
      detail = `Verified in ${formatDuration(total)} — proving ${formatDuration(state.provingMs)} + submit ${formatDuration(state.submitMs)}.`;
      testidBadge = "result-verified";
    } else {
      headline = "Proof rejected";
      detail = `Verifier responded in ${formatDuration(state.submitMs)} — not verified.`;
      tone = "error";
      testidBadge = "result-not-verified";
    }
  } else if (isError) {
    headline = "Error";
    detail = `${state.where}: ${state.message}`;
    tone = "error";
    testidBadge = "result-error";
  } else {
    // Router guards should prevent this branch; kept as a defensive fallback.
    headline = "";
    detail = "";
    testidBadge = "result-unknown";
  }

  root.innerHTML = `
    <section class="screen screen-result">
      <h1 data-testid="result-headline">${headline}</h1>
      <div class="result-banner" data-kind="${tone}" data-testid="${testidBadge}">
        <div class="result-line" data-testid="result-detail"></div>
      </div>
      <div class="button-row">
        <button class="secondary-button" data-testid="result-home" type="button">
          Home
        </button>
        <button class="primary-button" data-testid="result-prove-again" type="button">
          Prove again
        </button>
      </div>
    </section>
  `;

  root.querySelector<HTMLElement>('[data-testid="result-detail"]')!.textContent = detail;

  const homeBtn = root.querySelector<HTMLButtonElement>('[data-testid="result-home"]')!;
  const againBtn = root.querySelector<HTMLButtonElement>('[data-testid="result-prove-again"]')!;

  // From `result`, "Prove again" returns to setup so the PIN can be
  // re-verified (strict single-use: session Pin was consumed during the
  // previous sign). Card + warm runtime stay green. From `error`, the
  // full setup chain may be suspect — send the user back to landing.
  const onAgain = () => {
    if (isError) dispatch({ type: "reset" });
    else dispatch({ type: "retry_proving" });
  };
  const onHome = () => dispatch({ type: "reset" });

  againBtn.addEventListener("click", onAgain);
  homeBtn.addEventListener("click", onHome);

  return () => {
    againBtn.removeEventListener("click", onAgain);
    homeBtn.removeEventListener("click", onHome);
  };
}
