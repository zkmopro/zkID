import assert from "node:assert";
import { circomkit } from "../common";

const THRESHOLDS: Record<string, {
  file: string;
  template: string;
  params: number[];
  maxConstraints: number;
}> = {
  cert_chain_rs2048: {
    file: "cert_chain",
    template: "CertChainRSA256",
    params: [1024, 121, 17, 2048, 17, 2048, 128, 128, 20],
    maxConstraints: 2_200_000,
  },
  cert_chain_rs4096: {
    file: "cert_chain",
    template: "CertChainRSA256",
    params: [1280, 121, 34, 4096, 17, 2048, 128, 128, 20],
    maxConstraints: 2_500_000,
  },
  device_sig_rs2048: {
    file: "device_sig",
    template: "DeviceSigRSA256",
    params: [1536, 121, 17],
    maxConstraints: 1_050_000,
  },
};

describe("Constraint count regression guard", function () {
  for (const [name, cfg] of Object.entries(THRESHOLDS)) {
    it(`${name} stays below ${cfg.maxConstraints.toLocaleString()} constraints`, async function () {
      this.timeout(900_000);

      const circuit = await circomkit.WitnessTester(name, {
        file: cfg.file,
        template: cfg.template,
        params: cfg.params,
      });

      const count = await circuit.getConstraintCount();
      console.log(`  ${name}: ${count.toLocaleString()} constraints (ceiling: ${cfg.maxConstraints.toLocaleString()})`);

      assert.ok(
        count <= cfg.maxConstraints,
        `${name} constraint count ${count.toLocaleString()} exceeds ceiling ${cfg.maxConstraints.toLocaleString()}. ` +
        `If this increase is intentional, update THRESHOLDS in constraint_count.test.ts.`
      );
    });
  }
});
