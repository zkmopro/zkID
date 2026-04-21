// Submitting screen: spinner + live elapsed counter while prove-main.ts POSTs
// both proofs to /link-verify. Actual submission lives in prove-main.ts.

import { $state } from "../store";

function formatSeconds(ms: number): string {
  return `${(ms / 1_000).toFixed(1)} s`;
}

export function mountSubmitting(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-submitting">
      <h1>Sending proof</h1>
      <p class="intro">
        Posting both proofs to the verifier. Keep this tab open — the
        response should arrive within a few seconds.
      </p>
      <ol data-testid="step-list" class="step-list single-step">
        <li class="step" data-testid="step-submit" data-status="in_progress">
          <span class="step-icon" aria-hidden="true"></span>
          <span class="step-title">Submit to verifier</span>
          <span class="step-label" data-testid="submit-elapsed">0.0 s</span>
        </li>
      </ol>
    </section>
  `;

  const elapsedEl = root.querySelector<HTMLElement>('[data-testid="submit-elapsed"]')!;

  let rafId: number | null = null;
  function tick(): void {
    const state = $state.get();
    if (state.phase !== "submitting") return;
    elapsedEl.textContent = formatSeconds(performance.now() - state.startedAt);
    rafId = requestAnimationFrame(tick);
  }
  rafId = requestAnimationFrame(tick);

  return () => {
    if (rafId != null) cancelAnimationFrame(rafId);
  };
}
