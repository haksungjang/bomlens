// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Locator } from "@playwright/test";

/**
 * Wait for an element's own animations to finish before measuring it.
 *
 * Panels mount with `animate-fade-in`, and a contrast check taken mid-fade
 * reads the blended colour rather than the settled one — a real 4.6:1 pair
 * measures 4.23:1 and axe reports a violation that does not exist once the
 * animation ends. Call this after the element is visible and before any axe or
 * colour assertion.
 */
export async function waitForSettled(locator: Locator) {
  await locator.evaluate(async (el) => {
    await Promise.all(
      el.getAnimations().map((a) => a.finished.catch(() => undefined)),
    );
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}
