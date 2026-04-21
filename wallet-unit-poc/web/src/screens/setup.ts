// Setup screen: three click-driven panels gate Continue.
//
// Two-step HiPKI flow mirrors selfTest.htm:
//   1. "Detect readers" → popup CheckEnvir → enumerate slots → render
//      picker. User sees one row per reader with the card serial if
//      inserted, or a "no card" hint.
//   2. "Read card" (after picking a slot) → popup GetUserCert scoped to
//      that slotDescription → parse cert into CardContext → unlock PIN.
//
// Each step is one popup, one response, popup self-closes. Popup needs
// a user gesture so we never auto-trigger.

import { ensureAsset } from "../asset-download";
import { bytesToHex } from "../bytes";
import { escapeAttr, escapeText } from "../dom-utils";
import { humanBytes } from "../format";
import {
  probePkcs11Info,
  signTbs,
  type Pkcs11InfoResponse,
} from "../hipki-client";
import { CIRCUITS } from "../manifest";
import { Pin } from "../pin";
import { buildCardContext } from "../pipeline";
import {
  $hipki,
  $pin,
  dropStalePin,
  isCardReady,
  type HipkiState,
  type PinState,
  type ReaderSlot,
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

/** Attempts remaining for the next verify call. `error` carries the residual
 *  count from the last failure; everything else means we haven't burned an
 *  attempt yet, so the budget resets to the full `MAX_PIN_ATTEMPTS`. */
function attemptsRemainingFrom(state: PinState): number {
  return state.status === "error" ? state.attemptsRemaining : MAX_PIN_ATTEMPTS;
}

function summariseSlots(resp: Pkcs11InfoResponse): ReaderSlot[] {
  return (resp.slots ?? []).map((s) => ({
    slotDescription: s.slotDescription ?? "(unnamed reader)",
    cardSN: s.token?.serialNumber,
  }));
}

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
          <div class="panel-title">Card reader</div>
          <div class="panel-body" data-testid="hipki-body">Click to detect connected card readers.</div>
          <div class="panel-detail" data-testid="hipki-detail"></div>
          <div class="panel-readers" data-testid="hipki-readers" hidden></div>
          <div class="panel-actions">
            <button class="secondary-button" data-testid="hipki-detect" type="button">
              Detect readers
            </button>
            <button class="secondary-button" data-testid="hipki-read" type="button" hidden>
              Read card
            </button>
          </div>
        </div>
        <div class="setup-panel" data-testid="setup-pin">
          <div class="panel-title">PIN verification</div>
          <div class="panel-warning" data-testid="pin-warning">
            Wrong PIN three times will lock your Taiwan Citizen Card.
          </div>
          <div class="panel-body" data-testid="pin-body">Detect and read your card first.</div>
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
  const readersEl = root.querySelector<HTMLElement>('[data-testid="hipki-readers"]')!;
  const detectBtn = root.querySelector<HTMLButtonElement>('[data-testid="hipki-detect"]')!;
  const readBtn = root.querySelector<HTMLButtonElement>('[data-testid="hipki-read"]')!;
  const pinWarning = root.querySelector<HTMLElement>('[data-testid="pin-warning"]')!;
  const pinBody = root.querySelector<HTMLElement>('[data-testid="pin-body"]')!;
  const pinInput = root.querySelector<HTMLInputElement>('[data-testid="pin-input"]')!;
  const pinVerify = root.querySelector<HTMLButtonElement>('[data-testid="pin-verify"]')!;
  const pinPanel = root.querySelector<HTMLElement>('[data-testid="setup-pin"]')!;
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

  // Cache of the slot list last rendered so we can rebuild the DOM only
  // when the slot set itself changes, not on every selection change.
  // Rebuilding on selection would destroy focus and drop in-flight clicks
  // on adjacent rows.
  let renderedSlotsKey: string | null = null;

  function slotsKey(slots: ReaderSlot[]): string {
    return slots.map((s) => `${s.slotDescription}|${s.cardSN ?? ""}`).join("\n");
  }

  function paintReaders(slots: ReaderSlot[], selected: string | undefined): void {
    if (slots.length === 0) {
      renderedSlotsKey = null;
      readersEl.hidden = true;
      readersEl.textContent = "";
      return;
    }
    readersEl.hidden = false;
    const key = slotsKey(slots);
    if (key !== renderedSlotsKey) {
      renderedSlotsKey = key;
      readersEl.innerHTML = slots
        .map((s, i) => {
          const id = `hipki-slot-${i}`;
          const disabled = s.cardSN ? "" : "disabled";
          const cardLabel = s.cardSN
            ? `card ${s.cardSN}`
            : "no card inserted";
          return `
            <label class="reader-row${disabled ? " reader-row-disabled" : ""}">
              <input type="radio" name="hipki-slot" id="${id}"
                data-testid="${id}" value="${escapeAttr(s.slotDescription)}"
                ${disabled} />
              <span class="reader-name">${escapeText(s.slotDescription)}</span>
              <span class="reader-card">${escapeText(cardLabel)}</span>
            </label>
          `;
        })
        .join("");
      readersEl.querySelectorAll<HTMLInputElement>('input[type="radio"]').forEach((el) => {
        el.addEventListener("change", () => {
          const state = $hipki.get();
          if (state.status !== "readers_listed") return;
          $hipki.set({ ...state, selectedSlot: el.value });
        });
      });
    }
    // Sync `checked` without touching the rest of the DOM so focus and any
    // mid-flight click on a different row are preserved.
    readersEl.querySelectorAll<HTMLInputElement>('input[type="radio"]').forEach((el) => {
      el.checked = el.value === selected;
    });
  }

  function paintHipki(state: HipkiState): void {
    switch (state.status) {
      case "probing":
        hipkiBody.textContent = "Click to detect connected card readers.";
        hipkiDetail.textContent = "";
        readersEl.hidden = true;
        readersEl.innerHTML = "";
        detectBtn.textContent = "Detect readers";
        detectBtn.disabled = false;
        readBtn.hidden = true;
        readBtn.disabled = true;
        break;
      case "detecting":
        hipkiBody.textContent = "Asking HiPKI for the reader list…";
        hipkiDetail.textContent = "A small popup will appear briefly.";
        detectBtn.disabled = true;
        readBtn.hidden = true;
        break;
      case "not_installed":
        hipkiBody.textContent = "HiPKI client not detected";
        hipkiDetail.textContent = state.message
          ? state.message
          : "Install the HiPKI LocalSignServer on this machine and keep it running.";
        readersEl.hidden = true;
        readersEl.innerHTML = "";
        detectBtn.textContent = "Try again";
        detectBtn.disabled = false;
        readBtn.hidden = true;
        readBtn.disabled = true;
        break;
      case "readers_listed": {
        const insertedCount = state.slots.filter((s) => s.cardSN).length;
        if (state.slots.length === 0) {
          hipkiBody.textContent = "No card readers found";
          hipkiDetail.textContent = "Plug in a reader and try again.";
        } else if (insertedCount === 0) {
          hipkiBody.textContent = `${state.slots.length} reader(s) detected, no card inserted`;
          hipkiDetail.textContent = "Insert your card and click Detect again.";
        } else {
          hipkiBody.textContent = `${insertedCount} card(s) ready — pick one and click Read card`;
          hipkiDetail.textContent = state.serverVersion
            ? `LocalSignServer v${state.serverVersion}`
            : "";
        }
        paintReaders(state.slots, state.selectedSlot);
        detectBtn.textContent = "Re-detect";
        detectBtn.disabled = false;
        readBtn.hidden = false;
        readBtn.disabled = !state.selectedSlot;
        break;
      }
      case "reading":
        hipkiBody.textContent = `Reading card from ${state.slotDescription}…`;
        hipkiDetail.textContent = "A small popup will appear briefly.";
        detectBtn.disabled = true;
        readBtn.hidden = false;
        readBtn.disabled = true;
        break;
      case "card_ready":
        hipkiBody.textContent = `Card ${state.cardSN}${state.subjectDN ? ` — ${state.subjectDN}` : ""}`;
        hipkiDetail.textContent = state.serverVersion
          ? `LocalSignServer v${state.serverVersion}`
          : "";
        readersEl.hidden = true;
        readersEl.innerHTML = "";
        detectBtn.textContent = "Re-detect";
        detectBtn.disabled = false;
        readBtn.hidden = true;
        break;
    }
    refreshPinControls();
    refreshContinue();
  }

  function paintPin(state: PinState): void {
    // Reset modifier classes; each branch sets the one it needs.
    pinPanel.classList.remove("setup-panel-ok");
    pinBody.classList.remove("pin-body-ok", "pin-body-error");
    // The lock-warning is only relevant before success — hide it once
    // verified so the user gets a clean "ready" surface, not a red hint
    // that suggests their correct PIN was risky.
    pinWarning.hidden = state.status === "locked";

    switch (state.status) {
      case "pending":
        pinBody.textContent = isCardReady()
          ? "Enter your PIN, then Verify."
          : "Detect and read your card first.";
        break;
      case "verifying":
        pinBody.textContent = "Verifying via HiPKI popup…";
        break;
      case "locked":
        pinBody.textContent = "PIN verified. Ready to prove.";
        pinBody.classList.add("pin-body-ok");
        pinPanel.classList.add("setup-panel-ok");
        pinInput.value = "";
        break;
      case "error":
        if (state.attemptsRemaining <= 0) {
          pinBody.textContent =
            "Card is locked. Three wrong PINs were entered — unlock at a HiPKI kiosk.";
        } else {
          pinBody.textContent = `Error: ${state.message} (${state.attemptsRemaining} attempts left)`;
        }
        pinBody.classList.add("pin-body-error");
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
    const remaining = attemptsRemainingFrom(pinNow);
    const lockedOut = remaining <= 0 && !locked;
    pinInput.disabled = !ready || locked || verifying || lockedOut;
    const shortPin = pinInput.value.length < 6;
    pinVerify.disabled = !ready || locked || verifying || lockedOut || shortPin;
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

  // --- HiPKI two-step ------------------------------------------------

  async function detectReaders(): Promise<void> {
    dropStalePin();
    $hipki.set({ status: "detecting" });
    try {
      const resp = await probePkcs11Info();
      const slots = summariseSlots(resp);
      // Default selection: first slot with a card; otherwise first slot.
      const defaultSelect =
        slots.find((s) => s.cardSN)?.slotDescription ?? slots[0]?.slotDescription;
      $hipki.set({
        status: "readers_listed",
        slots,
        serverVersion: resp.serverVersion,
        selectedSlot: defaultSelect,
      });
    } catch (err) {
      $hipki.set({
        status: "not_installed",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function readSelectedCard(): Promise<void> {
    const state = $hipki.get();
    if (state.status !== "readers_listed" || !state.selectedSlot) return;
    const slotDescription = state.selectedSlot;
    dropStalePin();
    $hipki.set({ status: "reading", slotDescription });
    try {
      const detected = await buildCardContext(slotDescription);
      $hipki.set({
        status: "card_ready",
        card: detected.card,
        cardSN: detected.cardSN ?? "(no serial)",
        subjectDN: detected.subjectDN,
        serverVersion: state.serverVersion,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      $hipki.set({ status: "not_installed", message });
    }
  }

  // --- PIN verification ----------------------------------------------

  async function verifyPin(): Promise<void> {
    const hipkiState = $hipki.get();
    if (hipkiState.status !== "card_ready") return;
    const raw = pinInput.value;
    if (raw.length < 6 || raw.length > 8) return;

    const prior = $pin.get();
    const attemptsRemaining = attemptsRemainingFrom(prior);
    if (attemptsRemaining <= 0) return;

    const cardSN = hipkiState.cardSN;
    $pin.set({ status: "verifying", cardSN });
    const candidatePin = new Pin(raw);
    pinInput.value = "";

    try {
      const resp = await signTbs({
        tbs: PIN_TEST_TBS_HEX,
        pin: candidatePin.consume(),
        slotDescription: hipkiState.card.slotDescription,
      });
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
  const onDetect = () => void detectReaders();
  const onRead = () => void readSelectedCard();
  const onPinVerify = () => void verifyPin();
  const onPinInput = () => refreshPinControls();
  const onContinue = () => {
    if (continueBtn.disabled) return;
    dispatch({ type: "continue" });
  };
  const onBack = () => dispatch({ type: "reset" });

  assetsRetry.addEventListener("click", onAssetsRetry);
  detectBtn.addEventListener("click", onDetect);
  readBtn.addEventListener("click", onRead);
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
    readBtn.removeEventListener("click", onRead);
    pinVerify.removeEventListener("click", onPinVerify);
    pinInput.removeEventListener("input", onPinInput);
    continueBtn.removeEventListener("click", onContinue);
    backBtn.removeEventListener("click", onBack);
    unsubHipki();
    unsubPin();
  };
}

