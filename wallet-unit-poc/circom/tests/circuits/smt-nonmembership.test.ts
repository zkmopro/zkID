import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { fetchSMTProof, convertSMTProofToCircuitInputs } from "../../src/smt_proof";

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

describe("SMTNonMembershipVerifier", function () {
  let circuit: WitnessTester<
    ["root", "key", "siblings", "oldKey", "oldValue", "isOld0"],
    []
  >;

  before(async function () {
    if (!(await isServerRunning())) {
      console.log("SMT server not running at", SMT_SERVER, "— skipping");
      this.skip();
    }
    circuit = await circomkit.WitnessTester("SMTNonMembership", {
      file: "components/smt-nonmembership",
      template: "SMTNonMembershipVerifier",
      params: [SMT_DEPTH],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("should verify non-membership proof from moica server", async () => {
    const proof = await fetchSMTProof(SMT_SERVER, ISSUER_ID, SERIAL_NUMBER);
    const inputs = convertSMTProofToCircuitInputs(proof, SMT_DEPTH);

    const witness = await circuit.calculateWitness({
      root: inputs.smtRoot,
      key: inputs.serialNumber,
      siblings: inputs.smtSiblings,
      oldKey: inputs.smtOldKey,
      oldValue: inputs.smtOldValue,
      isOld0: inputs.smtIsOld0,
    });
    await circuit.expectConstraintPass(witness);
  });
});
