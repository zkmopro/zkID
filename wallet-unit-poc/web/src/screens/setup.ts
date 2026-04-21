// Setup screen: three click-driven panels gate Continue.
//
// HiPKI's `popupForm` bridge is single-shot: each request opens its own
// popup, gets one response, and the popup self-closes. So polling is not
// possible here — the user clicks "Detect card" once. On success the
// HiPKI panel shows the parsed CardContext and unlocks the PIN input. PIN
// verify is also one click, one popup. The asset preflight runs
// automatically since it does not need the popup.

import { ensureAsset } from "../asset-download";
import { bytesToHex } from "../bytes";
import { humanBytes } from "../format";
import { signTbs } from "../hipki-client";
import { CIRCUITS } from "../manifest";
import { Pin } from "../pin";
import { buildCardContext } from "../pipeline";
import {
  $hipki,
  $pin,
  isCardReady,
  type HipkiState,
  type PinState,
} from "../setup-state";
import { dispatch } from "../store";

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
        Three checks before proving. Each HiPKI step opens a small popup
        from your local card reader to bypass browser security restrictions.
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
          <div class="panel-body" data-testid="hipki-body">Click to detect your card.</div>
          <div class="panel-detail" data-testid="hipki-detail"></div>
          <div class="panel-actions">
            <button class="secondary-button" data-testid="hipki-detect" type="button">
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

  const assetsBody = root.querySelector<HTMLElement>('[data-testid="assets-body"]')!;
  const assetsRetry = root.querySelector<HTMLButtonElement>('[data-testid="assets-retry"]')!;
  const hipkiBody = root.querySelector<HTMLElement>('[data-testid="hipki-body"]')!;
  const hipkiDetail = root.querySelector<HTMLElement>('[data-testid="hipki-detail"]')!;
  const detectBtn = root.querySelector<HTMLButtonElement>('[data-testid="hipki-detect"]')!;
  const pinBody = root.querySelector<HTMLElement>('[data-testid="pin-body"]')!;
  const pinInput = root.querySelector<HTMLInputElement>('[data-testid="pin-input"]')!;
  const pinVerify = root.querySelector<HTMLButtonElement>('[data-testid="pin-verify"]')!;
  const backBtn = root.querySelector<HTMLButtonElement>('[data-testid="back-button"]')!;
  const continueBtn = root.querySelector<HTMLButtonElement>('[data-testid="continue-button"]')!;

  let assets: AssetsState = { status: "pending" };

  // --- Painters -------------------------------------------------------

  function paintAssets(): void {
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
    refreshContinue();
  }

  function paintHipki(state: HipkiState): void {
    switch (state.status) {
      case "probing":
        hipkiBody.textContent = "Click to detect your card.";
        hipkiDetail.textContent = "";
        detectBtn.textContent = "Detect card";
        detectBtn.disabled = false;
        break;
      case "detecting":
        hipkiBody.textContent = "Reading card via HiPKI popup…";
        hipkiDetail.textContent = "A small popup window will appear briefly.";
        detectBtn.disabled = true;
        break;
      case "not_installed":
        hipkiBody.textContent = "HiPKI client not detected";
        hipkiDetail.textContent = state.message
          ? state.message
          : "Install the HiPKI LocalSignServer on this machine and keep it running.";
        detectBtn.textContent = "Try again";
        detectBtn.disabled = false;
        break;
      case "no_reader":
        hipkiBody.textContent = "No card reader plugged in";
        hipkiDetail.textContent = state.serverVersion
          ? `LocalSignServer v${state.serverVersion}`
          : "";
        detectBtn.textContent = "Try again";
        detectBtn.disabled = false;
        break;
      case "no_reader_or_card":
        hipkiBody.textContent = "Reader present, but no card inserted";
        hipkiDetail.textContent =
          state.slots.length > 0
            ? `Reader: ${state.slots.join(", ")}`
            : "";
        detectBtn.textContent = "Try again";
        detectBtn.disabled = false;
        break;
      case "card_inserted":
        hipkiBody.textContent = `Card detected — ${state.cardSN}`;
        hipkiDetail.textContent = "Reading certificate…";
        detectBtn.disabled = true;
        break;
      case "card_ready":
        hipkiBody.textContent = `Card ${state.cardSN}${state.subjectDN ? ` — ${state.subjectDN}` : ""}`;
        hipkiDetail.textContent = state.serverVersion
          ? `LocalSignServer v${state.serverVersion}`
          : "";
        detectBtn.textContent = "Re-detect";
        detectBtn.disabled = false;
        break;
    }
    refreshPinControls();
    refreshContinue();
  }

  function paintPin(state: PinState): void {
    switch (state.status) {
      case "pending":
        pinBody.textContent = isCardReady()
          ? "Enter your PIN, then Verify."
          : "Detect your card first.";
        break;
      case "verifying":
        pinBody.textContent = "Verifying via HiPKI popup…";
        break;
      case "locked":
        pinBody.textContent = "PIN verified. Ready to prove.";
        pinInput.value = "";
        break;
      case "error":
        pinBody.textContent = `Error: ${state.message} (${state.attemptsRemaining} attempts left)`;
        break;
    }
    refreshPinControls();
    refreshContinue();
  }

  function refreshPinControls(): void {
    const ready = isCardReady();
    const pinNow = $pin.get();
    const locked = pinNow.status === "locked";
    const verifying = pinNow.status === "verifying";
    pinInput.disabled = !ready || locked || verifying;
    const shortPin = pinInput.value.length < 6;
    pinVerify.disabled = !ready || locked || verifying || shortPin;
  }

  function refreshContinue(): void {
    const pinNow = $pin.get();
    continueBtn.disabled = !(
      assets.status === "ok" &&
      isCardReady() &&
      pinNow.status === "locked"
    );
  }

  // --- Asset download -------------------------------------------------

  async function downloadAssets(): Promise<void> {
    assets = { status: "downloading", label: "starting", bytesDone: 0, bytesTotal: 0 };
    paintAssets();
    try {
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

  // --- HiPKI detect ---------------------------------------------------
  //
  // Each click opens a single popup that hits /pkcs11info?withcert=true
  // (via `buildCardContext` -> `fetchPkcs11Info` -> `popupPkcs11Info`),
  // returns one response, and self-closes. We discard any prior verified
  // PIN since it may not match the new card.

  function dropStalePin(): void {
    const pinNow = $pin.get();
    if (pinNow.status === "locked" || pinNow.status === "verifying") {
      $pin.set({ status: "pending" });
    }
  }

  async function detectCard(): Promise<void> {
    dropStalePin();
    $hipki.set({ status: "detecting" });
    try {
      const detected = await buildCardContext();
      $hipki.set({
        status: "card_ready",
        card: detected.card,
        cardSN: detected.cardSN ?? "(no serial)",
        subjectDN: detected.subjectDN,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // The popup closes itself after one response; a thrown error here
      // is almost always "popup blocked" or "popup timeout".
      $hipki.set({ status: "not_installed", message });
    }
  }

  // --- PIN verification -----------------------------------------------

  async function verifyPin(): Promise<void> {
    const hipkiState = $hipki.get();
    if (hipkiState.status !== "card_ready") return;
    const raw = pinInput.value;
    if (raw.length < 6 || raw.length > 8) return;

    const prior = $pin.get();
    const attemptsRemaining =
      prior.status === "error" ? prior.attemptsRemaining : MAX_PIN_ATTEMPTS;
    if (attemptsRemaining <= 0) return;

    const cardSN = hipkiState.cardSN;
    $pin.set({ status: "verifying", cardSN });
    const candidatePin = new Pin(raw);
    pinInput.value = "";

    try {
      const resp = await signTbs({ tbs: PIN_TEST_TBS_HEX, pin: candidatePin.consume() });
      if (resp.ret_code !== 0 || resp.last_error !== 0) {
        $pin.set({
          status: "error",
          message: `HiPKI rejected PIN (ret_code=${resp.ret_code})`,
          attemptsRemaining: attemptsRemaining - 1,
        });
        return;
      }
      $pin.set({
        status: "locked",
        pin: new Pin(raw),
        cardSN,
        attemptsRemaining,
      });
    } catch (err) {
      $pin.set({
        status: "error",
        message: err instanceof Error ? err.message : String(err),
        attemptsRemaining: attemptsRemaining - 1,
      });
    }
  }

  // --- Handlers + subscriptions ---------------------------------------

  const onAssetsRetry = () => void downloadAssets();
  const onDetect = () => void detectCard();
  const onPinVerify = () => void verifyPin();
  const onPinInput = () => refreshPinControls();
  const onContinue = () => {
    if (continueBtn.disabled) return;
    dispatch({ type: "continue" });
  };
  const onBack = () => dispatch({ type: "reset" });

  assetsRetry.addEventListener("click", onAssetsRetry);
  detectBtn.addEventListener("click", onDetect);
  pinVerify.addEventListener("click", onPinVerify);
  pinInput.addEventListener("input", onPinInput);
  continueBtn.addEventListener("click", onContinue);
  backBtn.addEventListener("click", onBack);

  const unsubHipki = $hipki.listen((state) => paintHipki(state));
  const unsubPin = $pin.listen((state) => paintPin(state));

  paintAssets();
  paintHipki($hipki.get());
  paintPin($pin.get());

  if (assets.status === "pending") void downloadAssets();

  return () => {
    assetsRetry.removeEventListener("click", onAssetsRetry);
    detectBtn.removeEventListener("click", onDetect);
    pinVerify.removeEventListener("click", onPinVerify);
    pinInput.removeEventListener("input", onPinInput);
    continueBtn.removeEventListener("click", onContinue);
    backBtn.removeEventListener("click", onBack);
    unsubHipki();
    unsubPin();
  };
}
