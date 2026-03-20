import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { fetchSMTProof, convertSMTProofToCircuitInputs } from "../../src/smt_proof";
import * as fs from "fs";
import * as path from "path";

const SMT_SERVER = "http://localhost:3000";
const ISSUER_ID = "g2";
const SERIAL_NUMBER = "0x639ACA88B568E0F7AAAC471953F962FD";
const SMT_DEPTH = 128;

async function isServerRunning(): Promise<boolean> {
  try {
    await fetch(SMT_SERVER);
    return true;
  } catch {
    return false;
  }
}

describe("CertRSA256VerifyWithRevocation", function () {
  let circuit: WitnessTester<
    [
      "message",
      "messageLength",
      "rsaModulus",
      "rsaSignature",
      "smtRoot",
      "serialNumber",
      "smtSiblings",
      "smtOldKey",
      "smtOldValue",
      "smtIsOld0"
    ],
    []
  >;

  before(async function () {
    const rs256InputPath = path.join(__dirname, "../../inputs/rs256/input.json");
    if (!fs.existsSync(rs256InputPath)) {
      console.log("RS256 test input not found at", rs256InputPath, "— skipping");
      this.skip();
    }
    if (!(await isServerRunning())) {
      console.log("SMT server not running at", SMT_SERVER, "— skipping");
      this.skip();
    }
    circuit = await circomkit.WitnessTester("rs256", {
      file: "rs256",
      template: "CertRSA256VerifyWithRevocation",
      params: [1536, 121, 17, SMT_DEPTH],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should verify RSA cert signature + SMT non-membership", async () => {
    const rs256InputPath = path.join(__dirname, "../../inputs/rs256/input.json");
    const rs256Input = JSON.parse(fs.readFileSync(rs256InputPath, "utf8"));

    const proof = await fetchSMTProof(SMT_SERVER, ISSUER_ID, SERIAL_NUMBER);
    const smtInputs = convertSMTProofToCircuitInputs(proof, SMT_DEPTH);

    const combinedInput = {
      ...rs256Input,
      smtRoot: smtInputs.smtRoot,
      serialNumber: smtInputs.serialNumber,
      smtSiblings: smtInputs.smtSiblings,
      smtOldKey: smtInputs.smtOldKey,
      smtOldValue: smtInputs.smtOldValue,
      smtIsOld0: smtInputs.smtIsOld0,
    };

    const witness = await circuit.calculateWitness(combinedInput);
    await circuit.expectConstraintPass(witness);
  });
});
