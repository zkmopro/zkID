import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";

describe("CertChainRSA256 (rs4096)", function () {
  let circuit: WitnessTester<
    [
      "user_cert_zero_padded",
      "tbs_modulus_offset",
      "tbs_modulus_tag_offset",
      "subject_dn",
      "tbs_subject_dn_offset",
      "subject_dn_length",
      "tbs_serial_number_offset",
      "issuer_tbs",
      "issuer_tbs_length",
      "actual_issuer_tbs_length",
      "issuer_rsa_modulus",
      "issuer_rsa_signature",
      "smtRoot",
      "serialNumber",
      "smtSiblings",
      "smtOldKey",
      "smtOldValue",
      "smtIsOld0",
      "pk_blind",
    ],
    ["pk_commit"]
  >;
  let input: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    input = loadInput("cert_chain_rs4096");
    circuit = await circomkit.WitnessTester("cert_chain_rs4096", {
      file: "cert_chain",
      template: "CertChainRSA256",
      params: [1536, 121, 34, 4096, 17, 2048, 128, 128, 20],
    });
  });

  it("should accept valid cert chain inputs", async function () {
    this.timeout(900_000);
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
  });
});
