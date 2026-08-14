// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Focus-trap arithmetic, kept out of the component so it can be tested without
 * a DOM. The component collects the focusable elements and applies the index
 * this returns.
 */

/** CSS selector for the elements a Tab press can reach. */
export const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "iframe",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/**
 * The index Tab should land on, wrapping at both ends so focus stays inside the
 * dialog.
 *
 * `current` is the index of the focused element, or -1 when focus sits on the
 * panel itself or has escaped the dialog — Tab then enters at the first element
 * and Shift+Tab at the last, which is what a user expects on re-entry.
 *
 * Returns null when there is nothing to focus, and the caller leaves the event
 * alone.
 */
export function wrapFocusIndex(
  count: number,
  current: number,
  backwards: boolean,
): number | null {
  if (count <= 0) return null;
  if (current < 0) return backwards ? count - 1 : 0;
  const next = backwards ? current - 1 : current + 1;
  if (next < 0) return count - 1;
  if (next >= count) return 0;
  return next;
}
