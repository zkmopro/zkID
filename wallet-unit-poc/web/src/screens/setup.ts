// Setup screen — Phase 3 skeleton.
//
// Phase 4 wires live asset-download progress, HiPKI detection, and PIN
// verification into the three panels. For now the panels are static
// placeholders and Continue is always enabled so the fixture-backed
// proving flow still runs end-to-end through the FSM.

import { dispatch } from "../store";

export function mountSetup(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-setup">
      <h1>Setup</h1>
      <p class="intro">
        Three checks run before proving. Phase 3 ships the UI skeleton;
        Phase 4 wires real HiPKI + SMT + asset-download progress.
      </p>
      <div class="setup-panels">
        <div class="setup-panel" data-testid="setup-assets">
          <div class="panel-title">Proving artifacts</div>
          <div class="panel-body">Cached on first run (Phase 4).</div>
        </div>
        <div class="setup-panel">
          <div class="panel-title">HiPKI card</div>
          <div class="panel-body">Detect card reader (Phase 4).</div>
        </div>
        <div class="setup-panel">
          <div class="panel-title">PIN verification</div>
          <div class="panel-body">Enter + test-sign PIN (Phase 4).</div>
        </div>
      </div>
      <div class="button-row">
        <button class="secondary-button" data-testid="back-button" type="button">
          Back
        </button>
        <button class="primary-button" data-testid="continue-button" type="button">
          Continue with fixtures
        </button>
      </div>
    </section>
  `;

  const continueBtn = root.querySelector<HTMLButtonElement>(
    '[data-testid="continue-button"]',
  );
  const backBtn = root.querySelector<HTMLButtonElement>(
    '[data-testid="back-button"]',
  );
  const onContinue = () => dispatch({ type: "continue" });
  const onBack = () => dispatch({ type: "reset" });
  continueBtn?.addEventListener("click", onContinue);
  backBtn?.addEventListener("click", onBack);
  return () => {
    continueBtn?.removeEventListener("click", onContinue);
    backBtn?.removeEventListener("click", onBack);
  };
}
