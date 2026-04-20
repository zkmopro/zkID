// The step atoms + result atom in `ui.ts` remain the source of truth for
// what each row paints. This screen hosts the container DOM and the Retry
// action; `mountSteps` does the actual painting.

import { dispatch, $state } from "../store";
import { mountSteps, resetUi } from "../ui";

export function mountProving(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-proving">
      <h1>Proving</h1>
      <p class="intro">
        The pipeline runs in a dedicated Worker. Rows below advance as the
        Worker reports progress.
      </p>
      <ol data-testid="step-list" id="step-list"></ol>
      <div id="result" data-testid="result"></div>
      <div class="button-row proving-actions" hidden data-testid="proving-actions">
        <button class="secondary-button" data-testid="retry-button" type="button">
          Retry
        </button>
      </div>
    </section>
  `;

  const listEl = root.querySelector<HTMLOListElement>(
    '[data-testid="step-list"]',
  )!;
  const resultEl = root.querySelector<HTMLElement>("#result")!;
  const actionsEl = root.querySelector<HTMLElement>(
    '[data-testid="proving-actions"]',
  )!;
  const retryBtn = root.querySelector<HTMLButtonElement>(
    '[data-testid="retry-button"]',
  )!;

  const disposeSteps = mountSteps(listEl, resultEl);

  const unsubState = $state.listen((state) => {
    actionsEl.hidden = !(state.phase === "result" || state.phase === "error");
  });

  const onRetry = () => {
    // Reset per-step atoms before the FSM swaps the screen away so the next
    // `proving` mount starts from a clean slate.
    resetUi();
    dispatch({ type: "reset" });
  };
  retryBtn.addEventListener("click", onRetry);

  return () => {
    retryBtn.removeEventListener("click", onRetry);
    unsubState();
    disposeSteps();
  };
}
