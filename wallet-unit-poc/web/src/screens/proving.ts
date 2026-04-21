// Proving screen: renders the 6-step proof-run list (main-thread pipeline
// steps + Worker per-circuit events). Step atoms in `ui.ts` are the source
// of truth. Cancel returns to setup, which drops the warm Worker.

import { dispatch } from "../store";
import { mountSteps } from "../ui";

export function mountProving(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-proving">
      <h1>Proving</h1>
      <p class="intro">
        The proof runs entirely in your browser. Signing requires a HiPKI
        popup from your local card reader. Per-step timing appears as each
        step completes.
      </p>
      <ol data-testid="step-list" id="step-list"></ol>
      <div id="result" data-testid="result"></div>
      <div class="button-row proving-actions">
        <button class="secondary-button" data-testid="proving-cancel" type="button">
          Cancel
        </button>
      </div>
    </section>
  `;

  const listEl = root.querySelector<HTMLOListElement>(
    '[data-testid="step-list"]',
  )!;
  const resultEl = root.querySelector<HTMLElement>("#result")!;
  const cancelBtn = root.querySelector<HTMLButtonElement>(
    '[data-testid="proving-cancel"]',
  )!;

  const disposeSteps = mountSteps(listEl, resultEl);

  const onCancel = () => {
    // Transitioning to setup drops the warm Worker (sign-main.ts handles
    // terminate on the phase change); Assets panel shows as "not warmed".
    dispatch({ type: "reset_to_setup" });
  };
  cancelBtn.addEventListener("click", onCancel);

  return () => {
    cancelBtn.removeEventListener("click", onCancel);
    disposeSteps();
  };
}
