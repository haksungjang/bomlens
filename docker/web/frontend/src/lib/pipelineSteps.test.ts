// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { pipelineStepLabelKey } from "./pipelineSteps";

describe("pipelineStepLabelKey", () => {
  it("returns an i18n key for a known step id", () => {
    expect(pipelineStepLabelKey("enrich-cpe")).toBe("pipelineSteps.enrichCpe");
    expect(pipelineStepLabelKey("generate-notice")).toBe("pipelineSteps.generateNotice");
  });

  it("covers every step id the dependency-lock designs and firmware (#82) use", () => {
    for (const step of [
      "firmware-packages",
      "firmware-extra-roots",
      "cargo-lockfile",
      "go-mod-tidy",
      "bundle-lock",
      "gradle-dependencies",
      "android-release-classpath",
      "swift-package-resolve",
      "npm-production-set",
      "pip-install",
      "cargo-workspace-metadata",
      "cargo-license-metadata",
      "composer-install",
      "pnpm-workspace-tree",
      "enrich-distro-supplier",
    ]) {
      expect(pipelineStepLabelKey(step)).toBeDefined();
    }
  });

  it("returns undefined for an unmapped step id, so the caller can fall back to the raw id", () => {
    expect(pipelineStepLabelKey("some-future-step")).toBeUndefined();
  });

  it("has a label for every step id the pipeline scripts can record as failed", () => {
    // docker/web/frontend is the working directory of the unit tests.
    const dockerDir = resolve(process.cwd(), "../..");
    const code = (file: string) =>
      readFileSync(resolve(dockerDir, file), "utf8")
        .split("\n")
        .filter((line) => !line.trim().startsWith("#"))
        .join("\n");
    const ids = new Set<string>();
    for (const m of code("lib/build-prep.sh").matchAll(/\bprep_step ([a-z][a-z0-9-]+) "/g)) ids.add(m[1]);
    for (const m of code("entrypoint.sh").matchAll(/\brun_optional_step ([a-z][a-z0-9-]+) /g)) ids.add(m[1]);
    expect(ids.size).toBeGreaterThan(20);
    const unlabelled = [...ids].filter((id) => pipelineStepLabelKey(id) === undefined);
    expect(unlabelled).toEqual([]);
  });
});
