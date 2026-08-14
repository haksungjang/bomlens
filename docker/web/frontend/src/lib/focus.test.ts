// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { FOCUSABLE_SELECTOR, wrapFocusIndex } from "./focus";

describe("wrapFocusIndex", () => {
  it("moves forward and wraps at the end", () => {
    expect(wrapFocusIndex(3, 0, false)).toBe(1);
    expect(wrapFocusIndex(3, 1, false)).toBe(2);
    expect(wrapFocusIndex(3, 2, false)).toBe(0);
  });

  it("moves backward and wraps at the start", () => {
    expect(wrapFocusIndex(3, 2, true)).toBe(1);
    expect(wrapFocusIndex(3, 0, true)).toBe(2);
  });

  it("enters at the near end when focus is outside the dialog", () => {
    expect(wrapFocusIndex(3, -1, false)).toBe(0);
    expect(wrapFocusIndex(3, -1, true)).toBe(2);
  });

  it("stays put with a single focusable element", () => {
    expect(wrapFocusIndex(1, 0, false)).toBe(0);
    expect(wrapFocusIndex(1, 0, true)).toBe(0);
  });

  it("returns null when there is nothing to focus", () => {
    expect(wrapFocusIndex(0, -1, false)).toBeNull();
    expect(wrapFocusIndex(0, 0, true)).toBeNull();
  });
});

describe("FOCUSABLE_SELECTOR", () => {
  it("excludes elements taken out of the tab order", () => {
    expect(FOCUSABLE_SELECTOR).toContain('[tabindex]:not([tabindex="-1"])');
    expect(FOCUSABLE_SELECTOR).toContain("button:not([disabled])");
  });
});
