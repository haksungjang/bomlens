import { test } from "@playwright/test";
import { killAnim, runScan, stubBackend } from "./helpers";

// Screenshot capture for the docs (run on demand: `npm run capture:ui`, excluded
// from the normal `test:ui` run via the @capture tag). Renders the
// --identify-vendored UI states deterministically with stubbed API responses and
// writes PNGs into docs/images/, so the guide screenshots are reproducible.
const IMAGES = "../../../docs/images";

const DONE = {
  ok: true,
  mode: "SOURCE",
  results: [{ name: "trelay_26.4.0_bom.json", size: 4096 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    suggestIdentifyVendored: true,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], vendored: true, matchConfidence: "100%" },
      { name: "liblfds", version: "6.1.1", group: "", purl: "pkg:github/liblfds/liblfds", type: "library", licenses: ["Unlicense"], vendored: true, matchConfidence: "100%" },
      { name: "libaes", version: "0.03", group: "", purl: "pkg:github/a/libaes", type: "library", licenses: [], vendored: true, matchConfidence: "92%" },
    ],
  },
};

test("@capture advanced toggle", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true } });
  await page.goto("/");
  await killAnim(page);
  await page.getByText("Advanced", { exact: true }).click();
  await page.getByText("Identify bundled open source").waitFor({ state: "visible" });
  await page.locator("details").screenshot({ path: `${IMAGES}/web-ui-identify-vendored-en.png` });
});

test("@capture result banner", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true }, done: DONE });
  await page.goto("/");
  await runScan(page, "trelay", "26.4.0");
  // The banner is the amber rounded-md box that holds the suggestion text.
  const banner = page
    .locator("div.rounded-md")
    .filter({ hasText: "is this C/C++ embedded source" })
    .first();
  await banner.waitFor({ state: "visible" });
  await killAnim(page);
  await page.evaluate(() => window.scrollTo(0, 0));
  await banner.screenshot({ path: `${IMAGES}/web-ui-vendored-banner-en.png` });
});

test("@capture vendored badge in components table", async ({ page }) => {
  await stubBackend(page, { caps: { scanoss: true }, done: DONE });
  await page.goto("/");
  await runScan(page, "trelay", "26.4.0");
  await page.getByRole("button", { name: /^Components/ }).click();
  const table = page.locator("table").first();
  await table.waitFor({ state: "visible" });
  await killAnim(page);
  await table.screenshot({ path: `${IMAGES}/web-ui-vendored-badge-en.png` });
});
