// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  EMPTY_SCAN,
  NAV_GROUPS,
  type ScanContext,
  visibleGroups,
  visibleSectionIds,
} from "./nav";

const SOURCE_SCAN: ScanContext = {
  mode: "SOURCE",
  isAiScan: false,
  hasDependencies: true,
  hasSourceTree: false,
  hasInputSbom: false,
  hasConformance: false,
};
const AI_SCAN: ScanContext = {
  mode: "ANALYZE",
  isAiScan: true,
  hasDependencies: true,
  hasSourceTree: true,
  hasInputSbom: true,
  hasConformance: true,
};
// A supplier SBOM uploaded for review (ANALYZE) with no AI model: it produces a
// conformance report but is not an AI scan.
const SUPPLIER_SBOM: ScanContext = {
  mode: "ANALYZE",
  isAiScan: false,
  hasDependencies: true,
  hasSourceTree: false,
  hasInputSbom: true,
  hasConformance: true,
};
// A plain source scan that (as of every mode running the check) still gets a
// conformance report on its OWN generated SBOM — no submitted document, no AI
// model. The report is a real file under Artifacts; it must not also claim a
// dedicated Compliance-group screen next to genuine facts about the scanned
// software (Components, Vulnerabilities, Licenses).
const GENERATED_SBOM: ScanContext = {
  mode: "SOURCE",
  isAiScan: false,
  hasDependencies: true,
  hasSourceTree: true,
  hasInputSbom: false,
  hasConformance: true,
};
// An AI SBOM BomLens generated itself (AIBOM/model-file/dataset) — no upload,
// so no submission to review. Its G7 minimum-element rollup is a real finding
// (the model publisher's own disclosure gaps, not a self-grade of a document
// BomLens wrote), but it lives on Models & datasets (AiSummaryCard + that
// section's own G7 detail), not on a Compliance-group Conformance screen.
const GENERATED_AI_SBOM: ScanContext = {
  mode: "AIBOM",
  isAiScan: true,
  hasDependencies: false,
  hasSourceTree: false,
  hasInputSbom: false,
  hasConformance: true,
};

describe("visibleGroups — scan-type + data adaptation", () => {
  it("shows the submitted-SBOM section only when the input was an SBOM", () => {
    // Reading a supplier's document is the one scan where the input itself is
    // worth a section; a source scan has a file tree instead.
    expect(visibleSectionIds(SUPPLIER_SBOM)).toContain("inputSbom");
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("inputSbom");
    expect(visibleSectionIds(EMPTY_SCAN)).not.toContain("inputSbom");
  });

  it("keeps the submitted SBOM beside the source tree, under Inventory", () => {
    const inventory = visibleGroups(SUPPLIER_SBOM).find((g) => g.id === "inventory");
    expect(inventory?.sections.map((s) => s.id)).toContain("inputSbom");
  });

  it("always shows the core sections", () => {
    const ids = visibleSectionIds(EMPTY_SCAN);
    expect(ids).toContain("overview");
    expect(ids).toContain("components");
    expect(ids).toContain("vulnerabilities");
    expect(ids).toContain("artifacts");
  });

  it("hides the models section for non-AI scans", () => {
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("models");
  });

  it("shows the models section only for AI scans", () => {
    expect(visibleSectionIds(AI_SCAN)).toContain("models");
  });

  it("shows conformance only for a submitted document, AI or not", () => {
    // Core supplier-SBOM fix: a non-AI SBOM with a conformance report still
    // reaches the conformance section (it lives under Compliance, not AI).
    expect(visibleSectionIds(SUPPLIER_SBOM)).toContain("conformance");
    // AI_SCAN is a submitted AI SBOM under review (hasInputSbom) — same rule.
    expect(visibleSectionIds(AI_SCAN)).toContain("conformance");
    const group = visibleGroups(SUPPLIER_SBOM).find((g) => g.id === "compliance");
    expect(group?.sections.map((s) => s.id)).toContain("conformance");
  });

  it("hides conformance for a plain generated SBOM even though a report exists", () => {
    // Not a submitted document (no _input.json) and no AI model: the report
    // stays a file in Artifacts rather than a Compliance-group verdict on
    // software it didn't judge.
    expect(visibleSectionIds(GENERATED_SBOM)).not.toContain("conformance");
  });

  it("hides conformance for a self-generated AI SBOM, but keeps Models & datasets", () => {
    // Its G7 rollup is real (the publisher's own disclosure gaps), but it
    // surfaces on Models & datasets, not as a Compliance-group verdict.
    expect(visibleSectionIds(GENERATED_AI_SBOM)).not.toContain("conformance");
    expect(visibleSectionIds(GENERATED_AI_SBOM)).toContain("models");
  });

  it("keeps conformance visible for a re-opened scan (mode arrives as null)", () => {
    // server.py sends "mode": null for anything but the run currently
    // streaming, so the gate must not key off `mode` — hasInputSbom/isAiScan
    // are derived from artifact presence and survive a re-open.
    expect(visibleSectionIds({ ...SUPPLIER_SBOM, mode: null })).toContain("conformance");
    expect(visibleSectionIds({ ...AI_SCAN, mode: null })).toContain("conformance");
    expect(visibleSectionIds({ ...GENERATED_SBOM, mode: null })).not.toContain("conformance");
  });

  it("keeps security and compliance apart", () => {
    // They are read by different people at different moments, so a CVE list and
    // a licence obligation must not sit in one group.
    const groups = visibleGroups(SOURCE_SCAN);
    const security = groups.find((g) => g.id === "security");
    const compliance = groups.find((g) => g.id === "compliance");
    expect(security?.sections.map((s) => s.id)).toEqual(["vulnerabilities"]);
    expect(compliance?.sections.map((s) => s.id)).toContain("licenses");
    expect(compliance?.sections.map((s) => s.id)).not.toContain("vulnerabilities");
    expect(groups.map((g) => g.id)).not.toContain("risk");
  });

  it("hides conformance when no conformance report exists", () => {
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("conformance");
    expect(
      visibleSectionIds({ ...AI_SCAN, hasConformance: false }),
    ).not.toContain("conformance");
  });

  it("gates dependencies/sourceTree on their data being present", () => {
    expect(visibleSectionIds(EMPTY_SCAN)).not.toContain("dependencies");
    expect(visibleSectionIds(EMPTY_SCAN)).not.toContain("sourceTree");
    expect(visibleSectionIds(SOURCE_SCAN)).toContain("dependencies");
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("sourceTree");
    expect(visibleSectionIds(AI_SCAN)).toContain("sourceTree");
  });

  it("drops a group that becomes empty after filtering (AI group on non-AI)", () => {
    expect(visibleGroups(SOURCE_SCAN).map((g) => g.id)).not.toContain("ai");
    expect(visibleGroups(AI_SCAN).map((g) => g.id)).toContain("ai");
  });

  it("preserves rail order and never mutates the source model", () => {
    const before = JSON.stringify(NAV_GROUPS.map((g) => g.sections.length));
    visibleGroups(AI_SCAN);
    expect(JSON.stringify(NAV_GROUPS.map((g) => g.sections.length))).toBe(before);
    expect(visibleSectionIds(EMPTY_SCAN)[0]).toBe("overview");
    expect(visibleSectionIds(AI_SCAN)[0]).toBe("overview");
  });
});
