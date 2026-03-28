import { WitnessTester } from "circomkit";
import { circomkit } from "../common";

const MAX_LEN = 64;
const MAX_SERIAL_LEN = 16;

describe("DERSerialExtractor", function () {
  this.timeout(120_000);

  let circuit: WitnessTester<
    ["in", "serialOffset", "serialLength"],
    ["serialNumber"]
  >;

  before(async function () {
    circuit = await circomkit.WitnessTester("DERSerialExtractor", {
      file: "components/serial-extractor",
      template: "DERSerialExtractor",
      params: [MAX_LEN, MAX_SERIAL_LEN],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  /**
   * Helper: build a zero-padded DER fragment with an INTEGER at `offset`.
   * Layout: ... | 0x02 | length | serial bytes ... | ...
   */
  function buildInput(
    serialBytes: number[],
    offset: number
  ): { in: number[]; serialOffset: number; serialLength: number } {
    const buf = new Array(MAX_LEN).fill(0);
    buf[offset] = 0x02; // INTEGER tag
    buf[offset + 1] = serialBytes.length; // 1-byte length
    for (let i = 0; i < serialBytes.length; i++) {
      buf[offset + 2 + i] = serialBytes[i];
    }
    return { in: buf, serialOffset: offset, serialLength: serialBytes.length };
  }

  /** Pack bytes big-endian into a BigInt, zero-extending to maxSerialLen. */
  function packBigEndian(bytes: number[], maxLen: number): bigint {
    let result = 0n;
    for (let i = 0; i < maxLen; i++) {
      result = result * 256n + BigInt(i < bytes.length ? bytes[i] : 0);
    }
    return result;
  }

  it("should extract a 16-byte serial number", async () => {
    const serial = [
      0x63, 0x9a, 0xca, 0x88, 0xb5, 0x68, 0xe0, 0xf7, 0xaa, 0xac, 0x47,
      0x19, 0x53, 0xf9, 0x62, 0xfd,
    ];
    const input = buildInput(serial, 4);
    const expected = packBigEndian(serial, MAX_SERIAL_LEN);
    await circuit.expectPass(input, { serialNumber: expected });
  });

  it("should extract an 8-byte serial number (shorter than max)", async () => {
    const serial = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const input = buildInput(serial, 0);
    const expected = packBigEndian(serial, MAX_SERIAL_LEN);
    await circuit.expectPass(input, { serialNumber: expected });
  });

  it("should extract a 1-byte serial number", async () => {
    const serial = [0x42];
    const input = buildInput(serial, 10);
    const expected = packBigEndian(serial, MAX_SERIAL_LEN);
    await circuit.expectPass(input, { serialNumber: expected });
  });

  it("should fail when tag byte is not 0x02", async () => {
    const serial = [0xaa, 0xbb];
    const input = buildInput(serial, 5);
    // Overwrite the tag to something wrong
    input.in[5] = 0x30; // SEQUENCE tag instead of INTEGER
    try {
      await circuit.calculateWitness(input);
      throw new Error("Should have failed");
    } catch (e: any) {
      if (e.message === "Should have failed") throw e;
      // Expected: constraint violation on tag check
    }
  });

  it("should produce different outputs for different serial numbers", async () => {
    const serial1 = [0x01, 0x02, 0x03, 0x04];
    const serial2 = [0x05, 0x06, 0x07, 0x08];
    const input1 = buildInput(serial1, 0);
    const input2 = buildInput(serial2, 0);

    const witness1 = await circuit.calculateWitness(input1);
    const witness2 = await circuit.calculateWitness(input2);

    const out1 = await circuit.readWitness(witness1, ["main.serialNumber"]);
    const out2 = await circuit.readWitness(witness2, ["main.serialNumber"]);

    if (out1["main.serialNumber"] === out2["main.serialNumber"]) {
      throw new Error("Different serials should produce different outputs");
    }
  });
});
