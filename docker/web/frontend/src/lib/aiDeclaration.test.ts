// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  bandSegments,
  checkValue,
  dateToDeclared,
  declaredToDate,
  emptyLocalDataset,
  issues,
  judgmentFields,
  modelMainFields,
  parseCheck,
  parseMap,
  remainingRequired,
  saveBlockers,
  slugFor,
  startDeclaration,
  stepOf,
  stepsFor,
  toFile,
  type Declaration,
  type FieldIndex,
} from "./aiDeclaration";

// The real mapping the converter uses, so a field added there is seen here.
const MAP = JSON.parse(
  readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8"),
) as unknown;
const index = parseMap(MAP) as FieldIndex;

// The empty declaration the converter writes for tests/fixtures/spdx3/bom-ai-sample.json.
const TEMPLATE = {
  schema: "bomlens-ai-declaration/1",
  document: { createdBy: [] },
  model: {
    releaseTime: "",
    builtTime: "",
    originatedBy: [],
    domain: [],
    informationAboutApplication: "",
    informationAboutTraining: "",
    hyperparameter: [],
    modelDataPreprocessing: [],
    modelExplainability: [],
    standardCompliance: [],
    useSensitivePersonalInformation: "",
    autonomyType: "",
    safetyRiskAssessment: "",
    baseModels: [
      { ref: "org/base-instruct", revision: "" },
      { ref: "org/base", revision: "" },
    ],
  },
  datasets: [
    { ref: "huggingface:org/open-ds", role: "", originatedBy: null, builtTime: "", releaseTime: "", knownBias: [] },
    { ref: "huggingface:org/upstream", originatedBy: null, builtTime: "", releaseTime: "", datasetType: [] },
  ],
  relationships: [],
};

const fresh = () => startDeclaration(TEMPLATE) as Declaration;

describe("parseMap", () => {
  it("reads every element's fields from the converter's mapping", () => {
    expect(index.document.createdBy).toMatchObject({ type: "Agent", min: 1, max: "*" });
    expect(index.ai_AIPackage.releaseTime).toMatchObject({ type: "DateTime", min: 1, max: 1 });
    expect(index.ai_AIPackage.useSensitivePersonalInformation).toMatchObject({ noAssertion: true, judgment: true });
    // The distributed weights have no "unknown": the vocabulary is ours.
    expect(index.ai_AIPackage.weightsScope.noAssertion).toBe(false);
    expect(index.dataset_DatasetPackage.datasetType.enum).toContain("noAssertion");
  });

  it("refuses a shape that is not the mapping", () => {
    expect(parseMap(null)).toBeNull();
    expect(parseMap({ elements: { document: { fields: [] } } })).toBeNull();
  });
});

describe("parseCheck and bandSegments", () => {
  it("keeps the fields the screens read and drops what it does not know", () => {
    const c = parseCheck({
      draft: true,
      counts: { auto: 3, declared: 1, optional: 2, judgment: 1, missingRequired: 2, noAssertion: 1, review: 1, bogus: 9 },
      elements: [
        { spdxId: "urn:m", type: "ai_AIPackage", label: "m", declarationKey: "model",
          fields: [{ id: "name", status: "auto", display: "m", source: "cdx:name" }, { id: "x", status: "weird" }, 7] },
        "junk",
        { spdxId: "urn:d", type: "dataset_DatasetPackage", label: "org/ds", fields: [] },
      ],
      relationships: [
        { type: "other", from: "urn:m", to: ["urn:d"], status: "review", note: "card-declared dataset, role not stated" },
      ],
      messages: [{ level: "review", text: "t" }, { level: "info" }],
    });
    expect(c).not.toBeNull();
    expect(c!.elements).toHaveLength(2);
    // A relationship names what it points to, for the screens.
    expect(c!.relationships[0].toLabel).toBe("org/ds");
    expect(c!.elements[0].declarationKey).toBe("model");
    expect(c!.elements[0].fields.map((f) => f.status)).toEqual(["auto", "omitted"]);
    expect(c!.counts).not.toHaveProperty("bogus");
    expect(c!.messages).toEqual([{ level: "review", text: "t" }]);
    expect(bandSegments(c!.counts)).toEqual([
      { key: "filled", count: 4 },
      { key: "optional", count: 4 },
      { key: "judgment", count: 1 },
      { key: "missingRequired", count: 2 },
    ]);
  });

  it("is null for anything but a check", () => {
    expect(parseCheck({ elements: [] })).toBeNull();
    expect(parseCheck("x")).toBeNull();
  });
});

describe("startDeclaration", () => {
  it("lays a saved declaration over the scan's empty one", () => {
    const saved = {
      schema: "bomlens-ai-declaration/1",
      document: { createdBy: [{ type: "Organization", name: "Acme" }] },
      model: {
        releaseTime: "2025-04-15T00:00:00Z",
        weightsScope: "adapter",
        baseModels: [
          { ref: "org/base-instruct", revision: "abc123" },
          { ref: "org/gone", revision: "zzz" },
        ],
      },
      datasets: [
        { ref: "huggingface:org/open-ds", role: "trainedOn", builtTime: "2023-10-01T00:00:00Z" },
        { ref: "huggingface:org/upstream", role: "trainedOn", releaseTime: "2022-02-01T00:00:00Z" },
        { ref: "huggingface:org/gone", builtTime: "2020-01-01T00:00:00Z" },
        { local: "logs", name: "Logs", role: "trainedOn" },
      ],
    };
    const d = startDeclaration(TEMPLATE, saved)!;
    expect(d.document.createdBy).toEqual([{ type: "Organization", name: "Acme" }]);
    expect(d.model!.releaseTime).toBe("2025-04-15T00:00:00Z");
    // A declared value the scan now fills itself is kept: it is still the
    // publisher's statement.
    expect(d.model!.weightsScope).toBe("adapter");
    // Revisions follow the base models this scan found; one it lost is dropped.
    expect(d.model!.baseModels).toEqual([
      { ref: "org/base-instruct", revision: "abc123" },
      { ref: "org/base", revision: "" },
    ]);
    expect(d.datasets.map((x) => x.ref ?? `local:${x.local}`)).toEqual([
      "huggingface:org/open-ds",
      "huggingface:org/upstream",
      "local:logs",
    ]);
    expect(d.datasets[0].role).toBe("trainedOn");
    // A traced source has no role slot, so a saved role is not carried onto it.
    expect(d.datasets[1]).not.toHaveProperty("role");
    expect(d.datasets[1].releaseTime).toBe("2022-02-01T00:00:00Z");
  });

  it("starts empty without a saved declaration, and is null for a bad template", () => {
    expect(fresh().model!.releaseTime).toBe("");
    expect(startDeclaration("nope")).toBeNull();
    expect(startDeclaration(TEMPLATE, "garbage")).toEqual(fresh());
  });
});

describe("issues and remainingRequired", () => {
  it("counts the required fields still empty, the author included unless the scan named one", () => {
    const d = fresh();
    const all = issues(index, d, false);
    // author, model release time, and per dataset: originatedBy, builtTime, releaseTime (+ datasetType on upstream)
    expect(remainingRequired(all)).toBe(1 + 1 + 3 + 4);
    expect(remainingRequired(issues(index, d, true))).toBe(8);
    // Optional fields never count.
    expect(all.some((i) => i.field === "informationAboutTraining" || i.field === "builtTime" && i.where === "model")).toBe(false);
  });

  it("reports a value the converter would refuse", () => {
    const d = fresh();
    d.model!.releaseTime = "2025-02-30T00:00:00Z";
    d.model!.hyperparameter = [
      { key: "lr", value: "1" },
      { key: "lr", value: "2" },
    ];
    d.model!.baseModels![0].revision = "not a revision!";
    d.datasets[1].datasetType = ["text", "noAssertion"];
    d.datasets[0].originatedBy = { type: "Organization", name: "  " };
    const got = issues(index, d, true).filter((i) => i.problem !== "required" || i.field === "originatedBy");
    expect(got).toEqual(
      expect.arrayContaining([
        { where: "model", field: "releaseTime", problem: "date" },
        { where: "model", field: "hyperparameter", problem: "duplicateKey" },
        { where: "model.baseModels[0]", field: "revision", problem: "revision" },
        { where: "datasets[1]", field: "datasetType", problem: "noAssertionMixed" },
        // An agent with a blank name is no answer: asked for again, and left
        // out of the saved file rather than refused by the server.
        { where: "datasets[0]", field: "originatedBy", problem: "required" },
      ]),
    );
  });

  it("leaves an added and untouched dataset out, and counts each open field of a started one once", () => {
    const d = fresh();
    d.datasets.push(emptyLocalDataset(index));
    expect(issues(index, d, true).filter((i) => i.where === "datasets[2]")).toEqual([]);
    d.datasets[2] = { ...d.datasets[2], local: "logs", name: "Logs" };
    const got = issues(index, d, true).filter((i) => i.where === "datasets[2]");
    expect(got.filter((i) => i.problem === "required").map((i) => i.field).sort()).toEqual(
      ["builtTime", "datasetType", "downloadLocation", "originatedBy", "releaseTime"],
    );
    // Without an address the server refuses the whole declaration.
    expect(saveBlockers(got)).toEqual([{ where: "datasets[2]", field: "local", problem: "localIncomplete" }]);
    d.datasets[2].downloadLocation = "https://data.example.com/logs";
    expect(saveBlockers(issues(index, d, true))).toEqual([]);
  });

  it("only a value the server would refuse blocks saving, not an open required field", () => {
    const d = fresh();
    expect(saveBlockers(issues(index, d, false))).toEqual([]);
    d.model!.releaseTime = "2025-13-01T00:00:00Z";
    expect(saveBlockers(issues(index, d, false))).toEqual([{ where: "model", field: "releaseTime", problem: "date" }]);
  });

  it("checks a revision as it will be saved (trimmed)", () => {
    const d = fresh();
    d.model!.baseModels![0].revision = "abc123 ";
    expect(issues(index, d, true).some((i) => i.field === "revision")).toBe(false);
  });

  it("counts text the way the converter does, in characters not UTF-16 units", () => {
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "😀".repeat(4000))).toBeNull();
  });
});

describe("checkValue", () => {
  it("follows the converter's address rules", () => {
    const f = index.ai_AIPackage.downloadLocation;
    expect(checkValue(f, "https://example.com/m")).toBeNull();
    expect(checkValue(f, "hf://org/m")).toBeNull();
    expect(checkValue(f, "file://host/etc/passwd")).toBe("uriScheme");
    // No host at all is not an absolute address, as the converter reads it.
    expect(checkValue(f, "file:///etc/passwd")).toBe("uri");
    expect(checkValue(f, "https://[::1")).toBe("uri");
    expect(checkValue(f, "https://[::1]/m")).toBeNull();
    expect(checkValue(f, "example.com/m")).toBe("uri");
    expect(checkValue(f, "https://a b")).toBe("uri");
    expect(checkValue(f, "")).toBeNull();
  });

  it("caps text at the converter's limit", () => {
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "x".repeat(4001))).toBe("tooLong");
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "x".repeat(4000))).toBeNull();
  });
});

describe("dates", () => {
  it("writes a picked day as midnight UTC and reads the day back", () => {
    expect(dateToDeclared("2025-04-15")).toBe("2025-04-15T00:00:00Z");
    expect(dateToDeclared("")).toBe("");
    expect(declaredToDate("2025-04-15T10:20:30Z")).toBe("2025-04-15");
    expect(declaredToDate(null)).toBe("");
  });
});

describe("toFile", () => {
  it("keeps only what was declared, and round-trips through startDeclaration", () => {
    const d = fresh();
    d.document.createdBy = [{ type: "Organization", name: " Acme " }];
    d.model!.releaseTime = "2025-04-15T00:00:00Z";
    d.model!.modelDataPreprocessing = ["masked", "  "];
    d.model!.baseModels![1].revision = "v1";
    d.datasets[0].role = "trainedOn";
    d.datasets.push({ ...emptyLocalDataset(index), local: "logs", name: "Logs" });
    const file = toFile(d);
    expect(file).toEqual({
      schema: "bomlens-ai-declaration/1",
      document: { createdBy: [{ type: "Organization", name: " Acme " }] },
      model: {
        releaseTime: "2025-04-15T00:00:00Z",
        modelDataPreprocessing: ["masked"],
        baseModels: [{ ref: "org/base", revision: "v1" }],
      },
      datasets: [
        { ref: "huggingface:org/open-ds", role: "trainedOn" },
        { local: "logs", name: "Logs" },
      ],
      relationships: [],
    });
    const again = startDeclaration(TEMPLATE, file)!;
    expect(toFile(again)).toEqual(file);
  });

  it("drops a setting row left blank and a dataset added but never filled", () => {
    const d = fresh();
    d.model!.hyperparameter = [
      { key: "lr", value: "2e-5" },
      { key: "", value: "" },
    ];
    d.datasets.push(emptyLocalDataset(index));
    const file = toFile(d);
    expect(file.model!.hyperparameter).toEqual([{ key: "lr", value: "2e-5" }]);
    expect(file.datasets).toEqual([]);
    expect(issues(index, d, true).some((i) => i.field === "hyperparameter")).toBe(false);
  });

  it("writes no model for a dataset scan", () => {
    const d = startDeclaration({ ...TEMPLATE, model: undefined })!;
    expect(toFile(d)).not.toHaveProperty("model");
  });
});

describe("steps", () => {
  it("asks base models, model, data, legal, preview for a model scan", () => {
    const d = fresh();
    expect(stepsFor(index, d)).toEqual(["base", "model", "data", "legal", "preview"]);
    expect(modelMainFields(index, d)).toEqual(["releaseTime", "builtTime", "originatedBy"]);
    expect(judgmentFields(index, d)).toEqual(["useSensitivePersonalInformation", "autonomyType", "safetyRiskAssessment"]);
  });

  it("asks only about the data for a dataset scan", () => {
    const d = startDeclaration({ ...TEMPLATE, model: undefined })!;
    expect(stepsFor(index, d)).toEqual(["data", "preview"]);
  });

  it("places an issue on the step that asks it", () => {
    expect(stepOf({ where: "document", field: "createdBy", problem: "required" })).toBe("model");
    expect(stepOf({ where: "model.baseModels[0]", field: "revision", problem: "revision" })).toBe("base");
    expect(stepOf({ where: "datasets[1]", field: "builtTime", problem: "required" })).toBe("data");
    expect(stepOf({ where: "model", field: "hyperparameter", problem: "duplicateKey" })).toBe("data");
    expect(stepOf({ where: "model", field: "autonomyType", problem: "required" })).toBe("legal");
    expect(stepOf({ where: "model", field: "releaseTime", problem: "required" })).toBe("model");
  });
});

describe("slugFor", () => {
  it("makes a file-safe slug and keeps it unique", () => {
    expect(slugFor("Support Logs 2025", [], 1)).toBe("support-logs-2025");
    expect(slugFor("Support Logs 2025", ["support-logs-2025"], 1)).toBe("support-logs-2025-2");
    expect(slugFor("고객상담 로그", [], 3)).toBe("dataset-3");
  });
});
