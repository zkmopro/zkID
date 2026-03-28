import { WitnessTester } from "circomkit";
import { circomkit } from "../common";

describe("ExtractSubjectDN", function () {
  this.timeout(120_000);

  let circuit: WitnessTester<
    ["in", "dnOffset", "dnLength"],
    ["dn", "dnLen"]
  >;

  before(async function () {
    circuit = await circomkit.WitnessTester("DNExtractor", {
      file: "components/dn-extractor",
      template: "ExtractSubjectDN",
      params: [64, 32],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  /**
   * Helper: build a zero-padded DER fragment with a SEQUENCE at `offset`.
   * Layout: ... | 0x30 | length | value bytes ... | ...
   */
  function buildInput(
    dnBytes: number[],
    offset: number
  ): { in: number[]; dnOffset: number; dnLength: number } {
    const buf = new Array(64).fill(0);
    buf[offset] = 0x30; // SEQUENCE tag
    buf[offset + 1] = dnBytes.length; // 1-byte length
    for (let i = 0; i < dnBytes.length; i++) {
      buf[offset + 2 + i] = dnBytes[i];
    }
    return { in: buf, dnOffset: offset, dnLength: dnBytes.length };
  }

  it("should extract a DN SEQUENCE", async () => {
    const dnBytes = [0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06];
    const input = buildInput(dnBytes, 2);

    const expectedDN = new Array(32).fill(0);
    for (let i = 0; i < dnBytes.length; i++) {
      expectedDN[i] = dnBytes[i];
    }

    await circuit.expectPass(input, { dn: expectedDN, dnLen: dnBytes.length });
  });

  it("should fail when tag byte is not 0x30", async () => {
    const dnBytes = [0x01, 0x02];
    const input = buildInput(dnBytes, 0);
    input.in[0] = 0x02; // Wrong tag
    try {
      await circuit.calculateWitness(input);
      throw new Error("Should have failed");
    } catch (e: any) {
      if (e.message === "Should have failed") throw e;
      // Expected constraint failure
    }
  });

  it("should zero-pad bytes beyond dnLength", async () => {
    const dnBytes = [0xaa, 0xbb, 0xcc];
    const input = buildInput(dnBytes, 0);

    const expectedDN = new Array(32).fill(0);
    expectedDN[0] = 0xaa;
    expectedDN[1] = 0xbb;
    expectedDN[2] = 0xcc;

    await circuit.expectPass(input, { dn: expectedDN, dnLen: 3 });
  });
});

describe("DNNullifierTest", function () {
  this.timeout(300_000);

  let circuit: WitnessTester<
    ["in", "dnOffset", "dnLength"],
    ["nullifier"]
  >;

  before(async function () {
    circuit = await circomkit.WitnessTester("NullifierTest", {
      file: "components/dn-nullifier",
      template: "DNNullifierTest",
      params: [512, 256],
      recompile: true,
    });
    console.log(
      "#constraints (nullifier):",
      await circuit.getConstraintCount()
    );
  });

  function buildInput(
    dnBytes: number[],
    offset: number,
    maxLen: number = 512
  ): { in: number[]; dnOffset: number; dnLength: number } {
    const buf = new Array(maxLen).fill(0);
    buf[offset] = 0x30; // SEQUENCE tag
    buf[offset + 1] = dnBytes.length;
    for (let i = 0; i < dnBytes.length; i++) {
      buf[offset + 2 + i] = dnBytes[i];
    }
    return { in: buf, dnOffset: offset, dnLength: dnBytes.length };
  }

  it("should be deterministic (same input -> same output)", async () => {
    const dnBytes = [0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06];
    const input = buildInput(dnBytes, 0);

    const w1 = await circuit.calculateWitness(input);
    const w2 = await circuit.calculateWitness(input);

    const out1 = await circuit.readWitness(w1, ["main.nullifier"]);
    const out2 = await circuit.readWitness(w2, ["main.nullifier"]);

    if (out1["main.nullifier"] !== out2["main.nullifier"]) {
      throw new Error("Same input should produce same nullifier");
    }
  });

  it("should produce different outputs for different DNs", async () => {
    const dn1 = [0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06];
    const dn2 = [0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07];
    const input1 = buildInput(dn1, 0);
    const input2 = buildInput(dn2, 0);

    const w1 = await circuit.calculateWitness(input1);
    const w2 = await circuit.calculateWitness(input2);

    const out1 = await circuit.readWitness(w1, ["main.nullifier"]);
    const out2 = await circuit.readWitness(w2, ["main.nullifier"]);

    if (out1["main.nullifier"] === out2["main.nullifier"]) {
      throw new Error("Different DNs should produce different nullifiers");
    }
  });
});
