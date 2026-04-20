// Setup screen with three live panels:
//   1. Artifact download — preflight-downloads PKs + witness-wasms so the
//      proving run can skip the network burst.
//   2. HiPKI detection — GET /pkcs11info, extract user + issuer cert,
//      derive issuer (g2/g3) + serial.
//   3. PIN verification — user types PIN, we issue a throwaway `sign` to
//      validate, then lock the input. Three retries before the card locks.

import { ensureAsset } from "../asset-download";
import { bytesToHex } from "../bytes";
import { humanBytes } from "../format";
import { signTbs } from "../hipki-client";
import { CIRCUITS } from "../manifest";
import { Pin } from "../pin";
import { buildCardContext } from "../pipeline";
import { $card, $pin, type CardState, type PinState } from "../setup-state";
import { dispatch } from "../store";

// Three attempts before the Taiwan Citizen Card locks. We count ourselves
// rather than relying on HiPKI's `last_error` codes since those vary across
// LocalSignServer builds.
const MAX_PIN_ATTEMPTS = 3;

/** HiPKI `/sign` rejects empty input, so we sign a stable non-empty string
 *  to validate the PIN without consuming a card challenge. */
const PIN_TEST_TBS_HEX = bytesToHex(
  new TextEncoder().encode("zkID-pin-test"),
);

type AssetsState =
  | { status: "pending" }
  | { status: "downloading"; label: string; bytesDone: number; bytesTotal: number }
  | { status: "ok" }
  | { status: "error"; message: string };

export function mountSetup(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-setup">
      <h1>Setup</h1>
      <p class="intro">
        Three checks before proving. Your PIN stays in this tab and is sent
        only to the HiPKI client on your machine.
      </p>
      <div class="setup-panels">
        <div class="setup-panel" data-testid="setup-assets">
          <div class="panel-title">Proving artifacts</div>
          <div class="panel-body" data-testid="assets-body">Ready to download.</div>
          <div class="panel-actions">
            <button class="secondary-button" data-testid="assets-retry" type="button">
              Download
            </button>
          </div>
        </div>
        <div class="setup-panel" data-testid="setup-hipki">
          <div class="panel-title">HiPKI card</div>
          <div class="panel-body" data-testid="hipki-body">Not yet detected.</div>
          <div class="panel-actions">
            <button class="secondary-button" data-testid="hipki-retry" type="button">
              Detect card
            </button>
          </div>
        </div>
        <div class="setup-panel" data-testid="setup-pin">
          <div class="panel-title">PIN verification</div>
          <div class="panel-warning">
            Wrong PIN three times will lock your Taiwan Citizen Card.
          </div>
          <div class="panel-body" data-testid="pin-body">Detect your card first.</div>
          <div class="panel-actions">
            <input
              class="pin-input"
              data-testid="pin-input"
              type="password"
              inputmode="numeric"
              pattern="[0-9]{6,8}"
              autocomplete="off"
              minlength="6"
              maxlength="8"
              placeholder="PIN"
              disabled
            />
            <button class="secondary-button" data-testid="pin-verify" type="button" disabled>
              Verify PIN
            </button>
          </div>
        </div>
      </div>
      <div class="button-row">
        <button class="secondary-button" data-testid="back-button" type="button">
          Back
        </button>
        <button class="primary-button" data-testid="continue-button" type="button" disabled>
          Continue
        </button>
      </div>
    </section>
  `;

  // Query nodes once. Template above is co-located with these lookups so
  // typing them non-null is safe; `!` kept for brevity.
  const assetsBody = root.querySelector<HTMLElement>('[data-testid="assets-body"]')!;
  const assetsRetry = root.querySelector<HTMLButtonElement>('[data-testid="assets-retry"]')!;
  const hipkiBody = root.querySelector<HTMLElement>('[data-testid="hipki-body"]')!;
  const hipkiRetry = root.querySelector<HTMLButtonElement>('[data-testid="hipki-retry"]')!;
  const pinBody = root.querySelector<HTMLElement>('[data-testid="pin-body"]')!;
  const pinInput = root.querySelector<HTMLInputElement>('[data-testid="pin-input"]')!;
  const pinVerify = root.querySelector<HTMLButtonElement>('[data-testid="pin-verify"]')!;
  const backBtn = root.querySelector<HTMLButtonElement>('[data-testid="back-button"]')!;
  const continueBtn = root.querySelector<HTMLButtonElement>('[data-testid="continue-button"]')!;

  let assets: AssetsState = { status: "pending" };
  const paintAssets = (): void => {
    switch (assets.status) {
      case "pending":
        assetsBody.textContent = "Ready to download.";
        assetsRetry.textContent = "Download";
        assetsRetry.disabled = false;
        break;
      case "downloading":
        assetsBody.textContent = `${assets.label} — ${humanBytes(assets.bytesDone, "0 B")} / ${humanBytes(assets.bytesTotal, "0 B")}`;
        assetsRetry.disabled = true;
        break;
      case "ok":
        assetsBody.textContent = "Cached. Ready to prove.";
        assetsRetry.textContent = "Re-download";
        assetsRetry.disabled = false;
        break;
      case "error":
        assetsBody.textContent = `Error: ${assets.message}`;
        assetsRetry.textContent = "Retry";
        assetsRetry.disabled = false;
        break;
    }
    updateContinueButton();
  };

  const paintHipki = (state: CardState): void => {
    switch (state.status) {
      case "pending":
        hipkiBody.textContent = "Not yet detected.";
        hipkiRetry.disabled = false;
        hipkiRetry.textContent = "Detect card";
        break;
      case "detecting":
        hipkiBody.textContent = "Contacting HiPKI LocalSignServer…";
        hipkiRetry.disabled = true;
        break;
      case "ok": {
        const subj = state.subjectDN ? ` — ${state.subjectDN}` : "";
        hipkiBody.textContent = `Card ${state.cardSN ?? "(no serial)"}${subj}`;
        hipkiRetry.disabled = false;
        hipkiRetry.textContent = "Re-detect";
        break;
      }
      case "error":
        hipkiBody.textContent = `Error: ${state.message}`;
        hipkiRetry.disabled = false;
        hipkiRetry.textContent = "Try again";
        break;
    }
    // PIN input is only usable once the card is detected.
    const cardOk = state.status === "ok";
    const pinNow = $pin.get();
    if (!cardOk) {
      pinInput.disabled = true;
      pinVerify.disabled = true;
      pinBody.textContent = "Detect your card first.";
    } else if (pinNow.status !== "locked") {
      pinInput.disabled = false;
      pinVerify.disabled = pinInput.value.length < 6;
    }
    updateContinueButton();
  };

  const paintPin = (state: PinState): void => {
    switch (state.status) {
      case "pending":
        pinBody.textContent = $card.get().status === "ok"
          ? "Enter your PIN, then Verify."
          : "Detect your card first.";
        break;
      case "verifying":
        pinBody.textContent = "Verifying…";
        pinVerify.disabled = true;
        break;
      case "locked":
        pinBody.textContent = "PIN verified. Ready to prove.";
        pinInput.value = "";
        pinInput.disabled = true;
        pinVerify.disabled = true;
        break;
      case "error":
        pinBody.textContent = `Error: ${state.message} (${state.attemptsRemaining} attempts left)`;
        pinVerify.disabled = pinInput.value.length < 6;
        break;
    }
    updateContinueButton();
  };

  function updateContinueButton(): void {
    const ready =
      assets.status === "ok" &&
      $card.get().status === "ok" &&
      $pin.get().status === "locked";
    continueBtn.disabled = !ready;
  }

  // --- asset download ---------------------------------------------------
  async function downloadAssets(): Promise<void> {
    assets = { status: "downloading", label: "starting", bytesDone: 0, bytesTotal: 0 };
    paintAssets();
    try {
      // Preflight-download all three circuits' PK + witness-wasm. The Worker
      // checks OPFS first, so this is strictly a UX move — progress is visible
      // before proving starts, and a failure here is a clear setup-phase error
      // rather than a mid-proof surprise.
      for (const key of Object.keys(CIRCUITS) as Array<keyof typeof CIRCUITS>) {
        const m = CIRCUITS[key];
        await ensureAsset(m.pkUrl, `${key}_pk`, m.expected.pk, (p) => {
          assets = {
            status: "downloading",
            label: `${key} pk`,
            bytesDone: p.bytesDone ?? 0,
            bytesTotal: p.bytesTotal ?? 0,
          };
          paintAssets();
        });
        await ensureAsset(m.witnessWasmUrl, `${key}_wgen`, m.expected.witnessWasm, (p) => {
          assets = {
            status: "downloading",
            label: `${key} witness-wasm`,
            bytesDone: p.bytesDone ?? 0,
            bytesTotal: p.bytesTotal ?? 0,
          };
          paintAssets();
        });
      }
      assets = { status: "ok" };
    } catch (err) {
      assets = { status: "error", message: err instanceof Error ? err.message : String(err) };
    }
    paintAssets();
  }

  // --- HiPKI detection --------------------------------------------------
  async function detectCard(): Promise<void> {
    $card.set({ status: "detecting" });
    try {
      const detected = await buildCardContext();
      $card.set({
        status: "ok",
        card: detected.card,
        subjectDN: detected.subjectDN,
        cardSN: detected.cardSN,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      $card.set({ status: "error", message });
    }
  }


  // --- PIN verification -------------------------------------------------
  async function verifyPin(): Promise<void> {
    const cardState = $card.get();
    if (cardState.status !== "ok") return;
    const raw = pinInput.value;
    if (raw.length < 6 || raw.length > 8) return;

    const prior = $pin.get();
    const attemptsRemaining =
      prior.status === "error" ? prior.attemptsRemaining : MAX_PIN_ATTEMPTS;
    if (attemptsRemaining <= 0) return;

    $pin.set({ status: "verifying" });
    // Wipe the input box immediately so a later render doesn't re-expose it.
    const candidatePin = new Pin(raw);
    pinInput.value = "";

    try {
      const resp = await signTbs({ tbs: PIN_TEST_TBS_HEX, pin: candidatePin.consume() });
      if (resp.ret_code !== 0 || resp.last_error !== 0) {
        const remaining = attemptsRemaining - 1;
        $pin.set({
          status: "error",
          message: `HiPKI rejected PIN (ret_code=${resp.ret_code})`,
          attemptsRemaining: remaining,
        });
        return;
      }
      // Happy path. Store a *fresh* Pin (the one we just consumed is spent)
      // so the proving run can issue its own /sign with a real challenge.
      $pin.set({
        status: "locked",
        pin: new Pin(raw),
        attemptsRemaining,
      });
    } catch (err) {
      const remaining = attemptsRemaining - 1;
      const message = err instanceof Error ? err.message : String(err);
      $pin.set({ status: "error", message, attemptsRemaining: remaining });
    }
  }

  // --- handlers + subscriptions ----------------------------------------
  const onAssetsRetry = () => {
    void downloadAssets();
  };
  const onHipkiRetry = () => {
    void detectCard();
  };
  const onPinVerify = () => {
    void verifyPin();
  };
  const onPinInput = () => {
    const cardOk = $card.get().status === "ok";
    const pinNow = $pin.get();
    pinVerify.disabled =
      !cardOk || pinNow.status === "locked" || pinInput.value.length < 6;
  };
  const onContinue = () => {
    if (continueBtn.disabled) return;
    dispatch({ type: "continue" });
  };
  const onBack = () => dispatch({ type: "reset" });

  assetsRetry.addEventListener("click", onAssetsRetry);
  hipkiRetry.addEventListener("click", onHipkiRetry);
  pinVerify.addEventListener("click", onPinVerify);
  pinInput.addEventListener("input", onPinInput);
  continueBtn.addEventListener("click", onContinue);
  backBtn.addEventListener("click", onBack);

  const unsubCard = $card.listen(paintCardAndRefresh);
  const unsubPin = $pin.listen(paintPinAndRefresh);
  function paintCardAndRefresh(state: CardState): void {
    paintHipki(state);
    paintPin($pin.get());
  }
  function paintPinAndRefresh(state: PinState): void {
    paintPin(state);
  }

  // Initial paint
  paintAssets();
  paintHipki($card.get());
  paintPin($pin.get());

  // Auto-kick asset download on first mount (but not on Retry re-mount when
  // the user bounced back to landing and clicked Start again — they can hit
  // Download manually).
  if (assets.status === "pending") void downloadAssets();
  // Auto-detect card if nothing's there yet; keep prior state otherwise.
  if ($card.get().status === "pending") void detectCard();

  return () => {
    assetsRetry.removeEventListener("click", onAssetsRetry);
    hipkiRetry.removeEventListener("click", onHipkiRetry);
    pinVerify.removeEventListener("click", onPinVerify);
    pinInput.removeEventListener("input", onPinInput);
    continueBtn.removeEventListener("click", onContinue);
    backBtn.removeEventListener("click", onBack);
    unsubCard();
    unsubPin();
  };
}

