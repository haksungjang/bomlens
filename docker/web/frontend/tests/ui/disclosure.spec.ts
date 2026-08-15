// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

/**
 * Two kinds of consistency that had drifted: how a section folds away, and how
 * a section says it has nothing to show.
 *
 * Three collapsible surfaces were each written out by hand, and the plainest of
 * them — the conformance crosswalk and its evidence — had no chevron at all, so
 * nothing on screen said they could be opened. Three empty states were bare
 * paragraphs while the rest of the app used the shared one.
 *
 * The assertions go at the shared components (their test ids) rather than at
 * the markup each site used to write, which is what makes a future site that
 * rolls its own visible here.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_4.0",
  // No artifacts: the Artifacts section's empty state is one of the three.
  results: [],
  security: null,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    checks: [
      {
        id: "g7-meta-author",
        label: "SBOM author",
        required: false,
        status: "pass",
        detail: "author present",
        cluster: "metadata",
        source: "auto",
        evidence: ["metadata.supplier.name"],
      },
      {
        id: "g7-meta-timestamp",
        label: "SBOM timestamp",
        required: false,
        status: "warn",
        detail: "missing",
        cluster: "metadata",
        source: "auto",
      },
    ],
  },
  sbom: { components: 0, componentList: [] },
};

async function open(page: Page, section: string) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan?id=demo_4.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.goto(`/?ui=next#/scan/demo_4.0/${section}`);
  await page.getByRole("navigation").first().waitFor();
}

test("a collapsible section shows that it can be opened, and opens", async ({ page }) => {
  await open(page, "conformance");

  const evidence = page.locator("details", { hasText: "Met with:" }).first();
  await expect(evidence).toBeVisible();
  // The chevron is the affordance: without it the row reads as plain text.
  await expect(evidence.locator("summary svg")).toBeVisible();
  await expect(evidence).not.toHaveAttribute("open", /.*/);

  await evidence.locator("summary").click();
  await expect(evidence).toHaveAttribute("open", "");
  await expect(evidence.getByText("metadata.supplier.name")).toBeVisible();

  await evidence.locator("summary").click();
  await expect(evidence).not.toHaveAttribute("open", /.*/);
});

test("a collapsible section opens from the keyboard", async ({ page }) => {
  await open(page, "conformance");
  const evidence = page.locator("details", { hasText: "Met with:" }).first();

  await evidence.locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(evidence).toHaveAttribute("open", "");
});

test("an empty section uses the shared empty state", async ({ page }) => {
  await open(page, "artifacts");
  await expect(page.getByTestId("empty-state")).toBeVisible();
});
