import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";

describe("DeviceSigRSA256 (rs2048)", function () {
  let circuit: WitnessTester<
    ["tbs", "tbs_length", "user_pk_limbs", "user_rsa_signature", "pk_blind"],
    ["pk_commit", "packed_tbs"]
  >;
  let input: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    input = loadInput("device_sig_rs2048");
    circuit = await circomkit.WitnessTester("device_sig_rs2048", {
      file: "device_sig",
      template: "DeviceSigRSA256",
      params: [1536, 121, 17],
    });
  });

  it("should accept valid device signature inputs", async function () {
    this.timeout(900_000);
    const witness = await circuit.calculateWitness(input);
    await circuit.expectConstraintPass(witness);
  });
});
