// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";

import { copyToClipboard, ISSUE_FORM_URL } from "./diagnostics";

describe("copyToClipboard", () => {
  it("writes the text and reports success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    expect(await copyToClipboard("hello", { clipboard: { writeText } })).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("reports failure when the clipboard rejects", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    expect(await copyToClipboard("x", { clipboard: { writeText } })).toBe(false);
  });

  it("reports failure when there is no clipboard API", async () => {
    expect(await copyToClipboard("x", {})).toBe(false);
    expect(await copyToClipboard("x", undefined)).toBe(false);
  });
});

describe("ISSUE_FORM_URL", () => {
  it("points at the YAML bug-report form on the public repository", () => {
    expect(ISSUE_FORM_URL).toBe(
      "https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml",
    );
  });
});
