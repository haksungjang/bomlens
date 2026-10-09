// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { parseMap, startDeclaration, type Declaration, type FieldIndex } from "./aiDeclaration";
import { declarationReducer, type DeclarationState } from "./useAiDeclaration";

const index = parseMap(
  JSON.parse(readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8")),
) as FieldIndex;

const start = (): DeclarationState => ({
  step: "model",
  decl: startDeclaration({
    schema: "bomlens-ai-declaration/1",
    document: { createdBy: [] },
    model: { releaseTime: "", baseModels: [{ ref: "org/base", revision: "" }] },
    datasets: [{ ref: "huggingface:org/ds", role: "", builtTime: "" }],
    relationships: [],
  }) as Declaration,
});

describe("declarationReducer", () => {
  it("sets an answer where it belongs without touching the rest", () => {
    const s0 = start();
    const s1 = declarationReducer(s0, { type: "set", target: { kind: "model" }, field: "releaseTime", value: "2025-01-01T00:00:00Z" });
    expect(s1.decl.model!.releaseTime).toBe("2025-01-01T00:00:00Z");
    expect(s0.decl.model!.releaseTime).toBe("");
    const s2 = declarationReducer(s1, { type: "set", target: { kind: "dataset", index: 0 }, field: "role", value: "trainedOn" });
    expect(s2.decl.datasets[0].role).toBe("trainedOn");
    const s3 = declarationReducer(s2, { type: "set", target: { kind: "base", index: 0 }, field: "revision", value: "abc" });
    expect(s3.decl.model!.baseModels).toEqual([{ ref: "org/base", revision: "abc" }]);
    const s4 = declarationReducer(s3, {
      type: "set",
      target: { kind: "document" },
      field: "createdBy",
      value: [{ type: "Organization", name: "Acme" }],
    });
    expect(s4.decl.document.createdBy).toEqual([{ type: "Organization", name: "Acme" }]);
  });

  it("ignores an answer for something that is not there", () => {
    const s0 = start();
    expect(declarationReducer(s0, { type: "set", target: { kind: "dataset", index: 9 }, field: "x", value: "" })).toBe(s0);
    expect(declarationReducer(s0, { type: "set", target: { kind: "base", index: 0 }, field: "ref", value: "other" })).toBe(s0);
  });

  it("adds a dataset the hub does not hold, slugs it from its name, and removes only those", () => {
    let s = declarationReducer(start(), { type: "addLocal", index });
    expect(s.decl.datasets).toHaveLength(2);
    s = declarationReducer(s, { type: "set", target: { kind: "dataset", index: 1 }, field: "name", value: "Support Logs" });
    expect(s.decl.datasets[1]).toMatchObject({ local: "support-logs", name: "Support Logs" });
    s = declarationReducer(s, { type: "addLocal", index });
    s = declarationReducer(s, { type: "set", target: { kind: "dataset", index: 2 }, field: "name", value: "Support logs" });
    expect(s.decl.datasets[2].local).toBe("support-logs-2");
    expect(declarationReducer(s, { type: "removeLocal", index: 0 })).toBe(s);
    s = declarationReducer(s, { type: "removeLocal", index: 1 });
    expect(s.decl.datasets.map((d) => d.local ?? d.ref)).toEqual(["huggingface:org/ds", "support-logs-2"]);
  });

  it("adds no dataset to a dataset scan, which has no model to relate it to", () => {
    const s0: DeclarationState = { step: "data", decl: { ...start().decl, model: undefined } };
    expect(declarationReducer(s0, { type: "addLocal", index })).toBe(s0);
  });

  it("moves between steps and resets", () => {
    const s = declarationReducer(start(), { type: "step", step: "preview" });
    expect(s.step).toBe("preview");
    const fresh = start().decl;
    expect(declarationReducer(s, { type: "reset", decl: fresh, step: "base" })).toEqual({ step: "base", decl: fresh });
  });
});
