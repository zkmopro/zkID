/// SMT Non-Membership Proof helpers for moica-revocation-smt server

export interface SMTProofResponse {
  root: string;
  entry: string[];
  matchingEntry: string[] | null;
  siblings: string[];
}

export interface SMTCircuitInputs {
  smtRoot: string;
  serialNumber: string;
  smtSiblings: string[];
  smtOldKey: string;
  smtOldValue: string;
  smtIsOld0: string;
}

/**
 * Convert a hex string (0x-prefixed) to a decimal string.
 */
function hexToDecimal(hex: string): string {
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    return BigInt(hex).toString(10);
  }
  return hex;
}

/**
 * Convert a moica-revocation-smt proof response to circuit inputs.
 * Handles both cases: matchingEntry present (isOld0=0) and absent (isOld0=1).
 * All hex values are converted to decimal strings for circom compatibility.
 */
export function convertSMTProofToCircuitInputs(
  proof: SMTProofResponse,
  depth: number
): SMTCircuitInputs {
  // Convert siblings to decimal and pad to the full tree depth
  const siblings = proof.siblings.map(hexToDecimal);
  while (siblings.length < depth) {
    siblings.push("0");
  }

  let oldKey: string;
  let oldValue: string;
  let isOld0: string;

  if (proof.matchingEntry != null && proof.matchingEntry.length >= 2) {
    // A different leaf exists at a nearby path
    oldKey = hexToDecimal(proof.matchingEntry[0]);
    oldValue = hexToDecimal(proof.matchingEntry[1]);
    isOld0 = "0";
  } else {
    // No leaf found — empty subtree
    oldKey = "0";
    oldValue = "0";
    isOld0 = "1";
  }

  return {
    smtRoot: hexToDecimal(proof.root),
    serialNumber: hexToDecimal(proof.entry[0]),
    smtSiblings: siblings,
    smtOldKey: oldKey,
    smtOldValue: oldValue,
    smtIsOld0: isOld0,
  };
}

/**
 * Fetch a non-membership proof from the moica-revocation-smt REST server.
 */
export async function fetchSMTProof(
  serverUrl: string,
  issuerId: string,
  serialNumber: string
): Promise<SMTProofResponse> {
  const url = `${serverUrl}/proof/${issuerId}/${serialNumber}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`SMT proof fetch failed: ${response.status} ${response.statusText}`);
  }
  return (await response.json()) as SMTProofResponse;
}
