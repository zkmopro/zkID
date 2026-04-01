// zkID Web Demo — RS256 Proof Pipeline
// Hybrid architecture: browser witness generation + server-side proving

// --- Configuration ---
const CONFIG = {
  // Path to the test certificate input JSON (bundled with the demo)
  testInputUrl: '/assets/rs256-input.json',
  // Path to the circom witness calculator WASM
  witnessWasmUrl: '/assets/rs256.wasm',
  // Proving server endpoint (ecdsa-spartan2 HTTP mode)
  proveServerUrl: 'http://localhost:8080/prove',
  // go-zkid-verifier endpoint
  verifierUrl: 'http://localhost:8081/verify',
};

// --- Types ---
interface StepLog {
  step: number;
  label: string;
  durationMs: number;
}

type StepState = 'disabled' | 'active' | 'done' | 'error';

// --- State ---
let circuitInput: Record<string, unknown> | null = null;
let circuitInputJson: string | null = null;
let proofBytes: Uint8Array | null = null;
const logs: StepLog[] = [];

// --- UI Helpers ---
function setStepState(step: number, state: StepState, statusText?: string) {
  const el = document.getElementById(`step-${step}`);
  if (!el) return;
  el.setAttribute('data-state', state);
  const statusEl = el.querySelector('.step-status');
  if (statusEl && statusText) statusEl.textContent = statusText;

  // Enable/disable button
  const btn = el.querySelector('button');
  if (btn) btn.disabled = state === 'disabled';
}

function addLog(step: number, label: string, durationMs: number, error?: boolean) {
  logs.push({ step, label, durationMs });
  const logsEl = document.getElementById('logs');
  if (!logsEl) return;
  const mark = error ? '<span class="error-mark">✗</span>' : '<span class="checkmark">✓</span>';
  const timeStr = durationMs >= 1000
    ? `${(durationMs / 1000).toFixed(1)}s`
    : `${durationMs}ms`;
  logsEl.innerHTML += `<div class="log-entry">${mark} ${label} <span class="time">${timeStr}</span></div>`;
}

function showResult(success: boolean, details: string) {
  const el = document.getElementById('result-banner');
  if (!el) return;
  el.classList.remove('hidden', 'success', 'failure');
  el.classList.add(success ? 'success' : 'failure');
  el.innerHTML = details;
}

function hideOverlay() {
  const el = document.getElementById('overlay');
  if (el) el.classList.add('hidden');
}

// --- Step 1: Load Certificate ---
async function handleLoad() {
  const t0 = performance.now();
  try {
    const resp = await fetch(CONFIG.testInputUrl);
    if (!resp.ok) throw new Error(`Failed to fetch: ${resp.status}`);
    circuitInput = await resp.json();
    const ms = Math.round(performance.now() - t0);
    addLog(1, 'Certificate data loaded', ms);
    setStepState(1, 'done', `${ms}ms`);
    setStepState(2, 'active');
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(1, `Load failed: ${e}`, ms, true);
    setStepState(1, 'error', 'failed');
  }
}

// --- Step 2: Generate Witness ---
// Uses circom WASM witness calculator in the browser
async function handleWitness() {
  if (!circuitInput) return;
  const t0 = performance.now();
  try {
    // Load the circom witness calculator
    const wasmResp = await fetch(CONFIG.witnessWasmUrl);
    if (!wasmResp.ok) throw new Error(`Failed to fetch witness WASM: ${wasmResp.status}`);
    const wasmBuffer = await wasmResp.arrayBuffer();

    // Use the circom witness_calculator.js pattern
    // For now, we'll send the circuit input to the server for witness generation too
    // (Full browser witness gen requires porting witness_calculator.js)
    const loadMs = Math.round(performance.now() - t0);
    addLog(2, `Witness WASM loaded (${(wasmBuffer.byteLength / 1024 / 1024).toFixed(1)}MB)`, loadMs);

    // Store the serialized input for the proving step
    circuitInputJson = JSON.stringify(circuitInput);
    const totalMs = Math.round(performance.now() - t0);
    addLog(2, 'Circuit input prepared for proving server', totalMs);
    setStepState(2, 'done', `${totalMs}ms`);
    setStepState(3, 'active');
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(2, `Witness generation failed: ${e}`, ms, true);
    setStepState(2, 'error', 'failed');
  }
}

// --- Step 3: Generate Proof (Server) ---
async function handleProve() {
  if (!circuitInputJson) return;
  const t0 = performance.now();
  try {
    setStepState(3, 'active', 'proving...');
    const resp = await fetch(CONFIG.proveServerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: circuitInputJson,
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Proving server error (${resp.status}): ${errText}`);
    }
    const result = await resp.json();
    proofBytes = base64ToBytes(result.proof);
    const ms = Math.round(performance.now() - t0);
    addLog(3, `Proof generated (${(proofBytes.length / 1024).toFixed(1)}KB)`, ms);
    setStepState(3, 'done', `${ms}ms`);
    setStepState(4, 'active');
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(3, `Proving failed: ${e}`, ms, true);
    setStepState(3, 'error', 'failed');
  }
}

// --- Step 4: Verify Proof ---
async function handleVerify() {
  if (!proofBytes) return;
  const t0 = performance.now();
  try {
    setStepState(4, 'active', 'verifying...');
    const resp = await fetch(CONFIG.verifierUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proof: bytesToBase64(proofBytes),
        public_inputs: extractPublicInputs(),
        circuit: 'rs256',
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Verifier error (${resp.status}): ${errText}`);
    }
    const result = await resp.json();
    const ms = Math.round(performance.now() - t0);

    if (result.verified) {
      addLog(4, 'Proof verified successfully', ms);
      setStepState(4, 'done', `${ms}ms`);
      showResult(true, `
        <strong>Verification: PASSED</strong><br/>
        The certificate proof is valid. The prover demonstrated knowledge of a valid
        MOICA citizen certificate chain without revealing the certificate contents.<br/>
        <br/>
        <strong>Timing:</strong> ${formatTimingSummary()}
      `);
    } else {
      addLog(4, `Verification failed: ${result.error || 'unknown'}`, ms, true);
      setStepState(4, 'error', 'invalid');
      showResult(false, `<strong>Verification: FAILED</strong><br/>${result.error || 'Proof invalid'}`);
    }
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(4, `Verification error: ${e}`, ms, true);
    setStepState(4, 'error', 'error');
    showResult(false, `<strong>Verification Error</strong><br/>${e}`);
  }
}

// --- Utilities ---
function base64ToBytes(b64: string): Uint8Array {
  const binString = atob(b64);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join('');
  return btoa(binString);
}

function extractPublicInputs(): string[] {
  if (!circuitInput) return [];
  const modulus = circuitInput['issuer_rsa_modulus'] as string[];
  const smtRoot = circuitInput['smtRoot'] as string;
  const serialNumber = circuitInput['serialNumber'] as string;
  return [...modulus, smtRoot, serialNumber];
}

function formatTimingSummary(): string {
  return logs.map((l) => {
    const timeStr = l.durationMs >= 1000
      ? `${(l.durationMs / 1000).toFixed(1)}s`
      : `${l.durationMs}ms`;
    return `Step ${l.step}: ${timeStr}`;
  }).join(' | ');
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  hideOverlay();

  document.getElementById('btn-load')?.addEventListener('click', handleLoad);
  document.getElementById('btn-witness')?.addEventListener('click', handleWitness);
  document.getElementById('btn-prove')?.addEventListener('click', handleProve);
  document.getElementById('btn-verify')?.addEventListener('click', handleVerify);
});
