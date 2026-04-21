import { describe, expect, it } from "vitest";

import {
  convertSmtProofToCircuitInputs,
  fetchSmtProof,
  SMT_DEPTH,
  type SmtCircuitInputs,
  type SmtProofResponse,
} from "./smt-client";

describe("convertSmtProofToCircuitInputs", () => {
  it("converts 0x-prefixed hex to decimal across every field", () => {
    const resp: SmtProofResponse = {
      root: "0x2a", // 42
      entry: ["0x270f"], // 9999
      matchingEntry: ["0x7", "0xb"], // 7, 11
      siblings: ["0x64", "0x65", "0xff"], // 100, 101, 255
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_root).toBe("42");
    expect(out.serial_number).toBe("9999");
    expect(out.smt_old_key).toBe("7");
    expect(out.smt_old_value).toBe("11");
    expect(out.smt_is_old0).toBe("0");
    expect(out.smt_siblings.slice(0, 3)).toEqual(["100", "101", "255"]);
    expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
    expect(out.smt_siblings.slice(3).every((s) => s === "0")).toBe(true);
  });

  it("accepts bare hex (no 0x prefix) — the form smt.wasm emits", () => {
    // `bigToHex` in moica-revocation-smt/server/wasm/main.go writes bare
    // hex via big.Int.Text(16); this is the contract the worker consumes.
    const resp: SmtProofResponse = {
      root: "2a",
      entry: ["270f"],
      matchingEntry: ["7", "b"],
      siblings: ["64", "65", "ff"],
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_root).toBe("42");
    expect(out.serial_number).toBe("9999");
    expect(out.smt_old_key).toBe("7");
    expect(out.smt_old_value).toBe("11");
    expect(out.smt_siblings.slice(0, 3)).toEqual(["100", "101", "255"]);
  });

  it("treats \"0\" consistently across prefix and bare forms", () => {
    const resp: SmtProofResponse = {
      root: "0",
      entry: ["0x0"],
      siblings: [],
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_root).toBe("0");
    expect(out.serial_number).toBe("0");
  });

  it("pads siblings to SMT_DEPTH with zeros", () => {
    const resp: SmtProofResponse = {
      root: "1",
      entry: ["2"],
      siblings: ["3"],
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
    expect(out.smt_siblings[0]).toBe("3");
    expect(out.smt_siblings[127]).toBe("0");
  });

  it("truncates siblings longer than depth", () => {
    const siblings = Array.from({ length: SMT_DEPTH + 5 }, (_, i) =>
      (i + 1).toString(16),
    );
    const resp: SmtProofResponse = {
      root: "1",
      entry: ["2"],
      siblings,
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
    expect(out.smt_siblings[0]).toBe("1");
  });

  it("sets smt_is_old0=1 when matchingEntry is absent", () => {
    const resp: SmtProofResponse = {
      root: "1",
      entry: ["2"],
      siblings: [],
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_old_key).toBe("0");
    expect(out.smt_old_value).toBe("0");
    expect(out.smt_is_old0).toBe("1");
  });

  it("sets smt_is_old0=1 when matchingEntry has < 2 elements", () => {
    const resp: SmtProofResponse = {
      root: "1",
      entry: ["2"],
      matchingEntry: ["7"],
      siblings: [],
    };
    const out = convertSmtProofToCircuitInputs(resp);
    expect(out.smt_is_old0).toBe("1");
  });

  it("accepts a custom depth", () => {
    const resp: SmtProofResponse = { root: "1", entry: ["2"], siblings: [] };
    const out = convertSmtProofToCircuitInputs(resp, 8);
    expect(out.smt_siblings).toHaveLength(8);
  });

  it("throws on empty entry array", () => {
    const resp = { root: "1", entry: [], siblings: [] } as SmtProofResponse;
    expect(() => convertSmtProofToCircuitInputs(resp)).toThrow(/empty entry/);
  });

  it("throws when siblings is missing", () => {
    const resp = { root: "1", entry: ["2"] } as unknown as SmtProofResponse;
    expect(() => convertSmtProofToCircuitInputs(resp)).toThrow(/siblings/);
  });
});

describe("fetchSmtProof (worker wrapper)", () => {
  function makeFakeWorker(options: {
    onProof?: (serialHex: string, requestId: string) => SmtProofResponse;
    onError?: (serialHex: string, requestId: string) => string;
  }): Worker {
    const listeners: Array<(ev: MessageEvent<unknown>) => void> = [];
    const worker = {
      postMessage(msg: unknown) {
        queueMicrotask(() => {
          const req = msg as {
            type: string;
            requestId: string;
            serialHex: string;
          };
          if (req.type !== "smt_proof") return;
          try {
            if (options.onError) {
              const message = options.onError(req.serialHex, req.requestId);
              dispatch({
                step: "smt_proof_error",
                requestId: req.requestId,
                message,
              });
              return;
            }
            const resp = options.onProof!(req.serialHex, req.requestId);
            dispatch({
              step: "smt_proof_done",
              requestId: req.requestId,
              inputs: convertSmtProofToCircuitInputs(resp),
            });
          } catch (err) {
            dispatch({
              step: "smt_proof_error",
              requestId: req.requestId,
              message: err instanceof Error ? err.message : String(err),
            });
          }
        });
      },
      addEventListener(
        _type: "message",
        listener: (ev: MessageEvent<unknown>) => void,
      ) {
        listeners.push(listener);
      },
      removeEventListener(
        _type: "message",
        listener: (ev: MessageEvent<unknown>) => void,
      ) {
        const idx = listeners.indexOf(listener);
        if (idx >= 0) listeners.splice(idx, 1);
      },
    } as unknown as Worker;
    function dispatch(data: unknown): void {
      const ev = { data } as MessageEvent<unknown>;
      for (const l of listeners.slice()) l(ev);
    }
    return worker;
  }

  it("resolves with circuit inputs on smt_proof_done", async () => {
    const worker = makeFakeWorker({
      onProof: (serialHex) => ({
        root: "2a",
        entry: [serialHex.replace(/^0x/i, "")],
        matchingEntry: ["7", "b"],
        siblings: ["64"],
      }),
    });
    const out: SmtCircuitInputs = await fetchSmtProof(worker, {
      issuer: "g2",
      serialHex: "0xdeadbeef",
    });
    expect(out.smt_root).toBe("42");
    expect(out.serial_number).toBe(BigInt("0xdeadbeef").toString(10));
    expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
    expect(out.smt_is_old0).toBe("0");
  });

  it("rejects on smt_proof_error with the worker's message", async () => {
    const worker = makeFakeWorker({
      onError: () => "engine not loaded",
    });
    await expect(
      fetchSmtProof(worker, { issuer: "g2", serialHex: "0x1" }),
    ).rejects.toThrow(/engine not loaded/);
  });

  it("rejects immediately when the signal is already aborted", async () => {
    const worker = makeFakeWorker({
      onProof: () => ({ root: "1", entry: ["2"], siblings: [] }),
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      fetchSmtProof(worker, { issuer: "g2", serialHex: "0x1", signal: controller.signal }),
    ).rejects.toThrow(/aborted/i);
  });

  it("rejects when the signal fires before the worker responds", async () => {
    // Worker that never responds.
    const worker = {
      postMessage() {},
      addEventListener() {},
      removeEventListener() {},
    } as unknown as Worker;
    const controller = new AbortController();
    const p = fetchSmtProof(worker, {
      issuer: "g2",
      serialHex: "0x1",
      signal: controller.signal,
    });
    controller.abort();
    await expect(p).rejects.toThrow(/aborted/i);
  });

  it("ignores messages intended for other requests", async () => {
    // Sequential requests must not cross-contaminate: the second request must
    // ignore the first's smt_proof_done reply.
    let seen = 0;
    const worker = makeFakeWorker({
      onProof: () => {
        seen += 1;
        return {
          root: seen.toString(16),
          entry: [seen.toString(16)],
          siblings: [],
        };
      },
    });
    const a = await fetchSmtProof(worker, { issuer: "g2", serialHex: "0x1" });
    const b = await fetchSmtProof(worker, { issuer: "g2", serialHex: "0x2" });
    expect(a.smt_root).toBe("1");
    expect(b.smt_root).toBe("2");
  });
});
