import fs from "fs";
import path from "path";

/** Load and parse a circuit input JSON, converting all numeric values to BigInt. */
export function loadInput(circuitName: string): Record<string, any> {
  const inputPath = path.resolve(
    __dirname,
    "../../inputs",
    circuitName,
    "input.json"
  );
  const raw = JSON.parse(fs.readFileSync(inputPath, "utf-8"));
  return convertToBigInt(raw);
}

function convertToBigInt(obj: any): any {
  if (typeof obj === "string" && /^\d+$/.test(obj)) return BigInt(obj);
  if (typeof obj === "number") return BigInt(obj);
  if (Array.isArray(obj)) return obj.map(convertToBigInt);
  if (typeof obj === "object" && obj !== null) {
    const result: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) result[k] = convertToBigInt(v);
    return result;
  }
  return obj;
}
