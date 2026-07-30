import { test, expect } from "@playwright/test";
import { runScan, stubBackend } from "./helpers";

// The --identify-vendored surfaces (Advanced toggle gating, result banner,
// vendored badge + match confidence, XSS escaping). The backend is stubbed so
// the UI renders deterministically (no Docker / network).
const VENDORED_DONE = {
  ok: true,
  mode: "SOURCE",
  results: [{ name: "testapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    suggestIdentifyVendored: true,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], vendored: true, matchConfidence: "100%" },
      { name: "<img src=x onerror=window.__xss=1>", version: "1.0", group: "", purl: "pkg:github/a/b", type: "library", licenses: [], vendored: true, matchConfidence: "88%" },
      { name: "express", version: "4.18.2", group: "", purl: "pkg:npm/express", type: "library", licenses: ["MIT"], vendored: false },
    ],
  },
};

test("Advanced vendored toggle is offered (collapsed by default) when scanoss is available", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true } });
  await page.goto("/");
  // Off-by-default UX: the toggle lives inside a collapsed "Advanced" disclosure,
  // so it is present but hidden until the user expands it.
  const toggle = page.getByText("Identify bundled open source");
  await expect(toggle).toHaveCount(1);
  await expect(toggle).toBeHidden();
  await page.getByText("Advanced", { exact: true }).click();
  await expect(toggle).toBeVisible();
});

test("Advanced vendored toggle hidden when scanoss is NOT available", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: false } });
  await page.goto("/");
  await expect(page.getByText("Identify bundled open source")).toHaveCount(0);
});

test("result banner appears for the C/C++ suggestion", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true }, done: VENDORED_DONE });
  await page.goto("/");
  await runScan(page, "testapp", "1.0");
  await expect(page.getByText(/is this C\/C\+\+ embedded source/i)).toBeVisible();
});

test("vendored badge + match confidence render; XSS name is inert", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true }, done: VENDORED_DONE });
  await page.goto("/");
  await runScan(page, "testapp", "1.0");
  // Open the Components tab where the per-component table (and badge) lives.
  await page.getByRole("button", { name: /^Components/ }).click();

  // vendored badge present with a match-confidence tooltip.
  const badge = page.getByText("vendored", { exact: true }).first();
  await expect(badge).toBeVisible();
  await expect(badge).toHaveAttribute("title", /match 100%/i);

  // The hostile component name renders as inert text, not an executed <img>.
  await expect(page.getByText("<img src=x onerror=window.__xss=1>")).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { __xss?: number }).__xss)).toBeUndefined();
  expect(await page.locator("img[onerror]").count()).toBe(0);
});
