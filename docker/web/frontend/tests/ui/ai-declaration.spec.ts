// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

// The SPDX 3.0.1 AI document on the Models & datasets screen: the band says
// how its fields were filled, and "Fill in empty fields" opens the questions
// for exactly the fields the scan left open. Saving goes to the server, which
// rewrites the document; the band then follows.

const MAP = readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8");
const P = "model_1.0";

const field = (id: string, status: string, display?: string) => ({ id, status, ...(display ? { display } : {}) });

function check(complete: boolean) {
  return {
    schema: "bomlens-spdx3-check/1",
    draft: !complete,
    counts: { auto: 8, declared: complete ? 6 : 0, optional: 10, judgment: complete ? 2 : 3,
              missingRequired: complete ? 0 : 5, noAssertion: 0, omitted: 2, review: 1 },
    elements: [
      { spdxId: "urn:doc", type: "CreationInfo", label: "document", declarationKey: "document",
        fields: [complete ? field("createdBy", "declared", "Acme AI Lab") : field("createdBy", "missingRequired")] },
      { spdxId: "urn:m", type: "ai_AIPackage", label: "acme/model", declarationKey: "model",
        fields: [
          field("name", "auto", "acme/model"),
          field("downloadLocation", "auto", "https://huggingface.co/acme/model"),
          { ...field("suppliedBy", "auto", "acme"), meaning: "huggingface-publisher" },
          complete ? field("releaseTime", "declared", "2025-04-15T00:00:00Z") : field("releaseTime", "missingRequired"),
          field("informationAboutTraining", "optional"),
          field("safetyRiskAssessment", "judgment"),
        ] },
      { spdxId: "urn:d", type: "dataset_DatasetPackage", label: "org/ds", declarationKey: "huggingface:org/ds",
        fields: [field("name", "auto", "org/ds"), field("suppliedBy", "auto", "org"),
                 field("downloadLocation", "auto", "https://huggingface.co/datasets/org/ds"),
                 field("originatedBy", complete ? "declared" : "missingRequired"),
                 field("builtTime", complete ? "declared" : "missingRequired"),
                 field("releaseTime", complete ? "declared" : "missingRequired")] },
    ],
    relationships: [{ type: "other", from: "urn:m", to: ["urn:d"], status: "review",
                      note: "card-declared dataset, role not stated" }],
    messages: [],
    declaration: { state: complete ? "applied" : "none" },
  };
}

const summary = (complete: boolean) => ({
  draft: !complete,
  counts: check(complete).counts,
  name: `${P}_bom.spdx3.json`,
  check: `${P}_spdx3-check.json`,
  declaration: { state: complete ? "applied" : "none", reasons: [] },
});

const TEMPLATE = {
  schema: "bomlens-ai-declaration/1",
  document: { createdBy: [] },
  model: {
    releaseTime: "", builtTime: "", originatedBy: [], weightsScope: "",
    domain: [], informationAboutApplication: "", informationAboutTraining: "", hyperparameter: [],
    modelDataPreprocessing: [], modelExplainability: [], standardCompliance: [],
    useSensitivePersonalInformation: "", autonomyType: "", safetyRiskAssessment: "",
    baseModels: [{ ref: "org/base", revision: "" }],
  },
  datasets: [{ ref: "huggingface:org/ds", role: "", originatedBy: null, builtTime: "", releaseTime: "",
               hasSensitivePersonalInformation: "", intendedUse: "" }],
  relationships: [],
};

const RESULTS = [
  { name: `${P}_bom.json`, size: 200 },
  { name: `${P}_bom.spdx3.json`, size: 300 },
  { name: `${P}_spdx3-check.json`, size: 100 },
  { name: `${P}_ai-declaration.template.json`, size: 100 },
];

const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  metadata: { component: { type: "machine-learning-model", "bom-ref": "m", name: "acme/model" } },
  components: [{ type: "data", "bom-ref": "dataset:huggingface/org/ds", name: "org/ds" }],
  dependencies: [{ ref: "m", dependsOn: ["dataset:huggingface/org/ds"] }],
};

async function stub(
  page: Page,
  opts: { capable?: boolean; withSummary?: boolean; saved?: unknown; refuse?: string[]; declared?: boolean } = {},
) {
  const state = { complete: false, saved: null as unknown, exported: 0 };
  const results = opts.saved ? [...RESULTS, { name: `${P}_ai-declaration.json`, size: 50 }] : RESULTS;
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdx3: opts.capable !== false }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  const done = {
    ok: true, mode: "AIBOM", id: P, results, security: null, conformance: null,
    spdx3: opts.withSummary === false ? null : summary(false),
    scanConfig: opts.declared
      ? { source: "ai-declare", target: "", project: "model", version: "1.0" }
      : { source: "hf-model", target: "acme/model", project: "model", version: "1.0" },
    sbom: { components: 1, componentType: "machine-learning-model",
            componentList: [{ name: "acme/model", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: [] }] },
  };
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
  await page.route("**/file**", (r) => {
    const name = new URL(r.request().url()).searchParams.get("name") ?? "";
    const body = name.endsWith("_spdx3-check.json")
      ? check(state.complete)
      : name.endsWith(".template.json")
        ? TEMPLATE
        : name.endsWith("_ai-declaration.json")
          ? opts.saved
          : SBOM;
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.route("**/spdx3-map", (r) => r.fulfill({ contentType: "application/json", body: MAP }));
  await page.route("**/ai-declaration-template**", (r) =>
    r.fulfill({ contentType: "application/json",
                body: JSON.stringify({ name: `${P}_ai-declaration.template.json`, results: RESULTS }) }),
  );
  await page.route("**/spdx3-export**", (r) => {
    state.exported += 1;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: `${P}_bom.spdx3.json`, results, spdx3: summary(state.complete) }),
    });
  });
  await page.route("**/ai-declaration?**", (r) => {
    state.saved = JSON.parse(r.request().postData() ?? "null");
    if (opts.refuse) {
      return r.fulfill({ status: 422, contentType: "application/json",
                         body: JSON.stringify({ error: "declaration refused", reasons: opts.refuse }) });
    }
    state.complete = true;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        name: `${P}_bom.spdx3.json`,
        results: [...RESULTS, { name: `${P}_ai-declaration.json`, size: 50 }],
        spdx3: summary(true),
      }),
    });
  });
  return state;
}

async function openModels(page: Page) {
  await page.goto("/#/new");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  await page.getByRole("navigation").locator('a[href$="/models"]').first().click();
}

test("the band shows how the fields were filled and the model's open fields", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const band = page.getByTestId("spdx3-band");
  await expect(band).toContainText("Draft");
  await expect(band.locator('[data-segment="missingRequired"]')).toContainText("5");
  await expect(band.locator('[data-segment="filled"]')).toContainText("8");
  await expect(band).toContainText("5 required fields are still empty");
  const release = page.locator('tr[data-field="releaseTime"]').first();
  await expect(release).toContainText("Required, empty");
  await expect(page.locator('tr[data-field="suppliedBy"]').first()).toContainText("HuggingFace publisher");
  await expect(page.getByText("Training or evaluation not stated")).toBeVisible();
});

test("filling the open fields: only what is open is asked, and saving completes the document", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  await page.getByRole("button", { name: "Fill in empty fields" }).click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow).toBeVisible();

  // Base models: a revision box for each, and leaving it empty is fine.
  await expect(flow.getByLabel("Revision (commit or tag, optional)")).toHaveCount(1);
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Model: the author and release date fail validation while empty; the
  // weights question has no "Unknown"; the optional group starts folded.
  await expect(flow.locator('[data-question="document.createdBy"]')).toContainText("fails SPDX validation");
  await expect(flow.locator('[data-question="model.releaseTime"]')).toContainText("fails SPDX validation");
  await expect(flow.locator('[data-question="model.weightsScope"]').getByRole("radio")).toHaveCount(4);
  await expect(flow.locator('[data-question="model.weightsScope"]').getByText("Unknown")).toHaveCount(0);
  await expect(flow.locator("details").filter({ hasText: "Use and scope (optional)" })).not.toHaveAttribute("open", "");
  await expect(flow).toContainText("5 required fields left");
  await flow.locator('[data-question="document.createdBy"] input').first().fill("Acme AI Lab");
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await flow.locator('[data-question="model.weightsScope"]').getByRole("radio", { name: "Adapter only" }).click();
  await expect(flow).toContainText("3 required fields left");
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Data: a role for the card's dataset; "Unknown" only on the personal-data
  // question, which has one; the training group folded and not counted.
  await flow.getByRole("radio", { name: "Training" }).click();
  await expect(flow.locator('[data-question="dataset.hasSensitivePersonalInformation"]').getByText("Unknown")).toHaveCount(1);
  await expect(flow.locator("details").filter({ hasText: "How it was trained (optional)" })).not.toHaveAttribute("open", "");
  await flow.locator('[data-question="dataset.originatedBy"] input').fill("org");
  await flow.locator('[data-question="dataset.builtTime"] input').fill("2023-10-01");
  await flow.locator('[data-question="dataset.releaseTime"] input').fill("2023-10-24");
  await expect(flow).toContainText("0 required fields left");
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Decisions: "Unknown" exists for personal data, not for the risk level.
  await expect(flow.locator('[data-question="model.useSensitivePersonalInformation"]').getByText("Unknown")).toHaveCount(1);
  await expect(flow.locator('[data-question="model.safetyRiskAssessment"]').getByText("Unknown")).toHaveCount(0);
  await flow.locator('[data-question="model.safetyRiskAssessment"]').getByRole("radio", { name: "Medium" }).click();
  await flow.getByRole("button", { name: /^Next/ }).click();

  await expect(flow).toContainText("Every required field is filled");
  await flow.getByRole("button", { name: "Save" }).click();

  await expect(page.getByTestId("spdx3-band")).toContainText("Complete");
  await expect(page.getByTestId("spdx3-band")).not.toContainText("Draft");
  expect(state.saved).toEqual({
    schema: "bomlens-ai-declaration/1",
    document: { createdBy: [{ type: "Organization", name: "Acme AI Lab" }] },
    model: { releaseTime: "2025-04-15T00:00:00Z", weightsScope: "adapter", safetyRiskAssessment: "medium" },
    datasets: [{ ref: "huggingface:org/ds", role: "trainedOn", originatedBy: { type: "Organization", name: "org" },
                 builtTime: "2023-10-01T00:00:00Z", releaseTime: "2023-10-24T00:00:00Z" }],
    relationships: [],
  });
});

test("a scan from before the document offers to write it", async ({ page }) => {
  await stub(page, { withSummary: false });
  await openModels(page);
  await expect(page.getByRole("button", { name: "Write the SPDX 3.0.1 document" })).toBeVisible();
});

test("a server that cannot write the document hides the actions", async ({ page }) => {
  await stub(page, { capable: false });
  await openModels(page);
  await expect(page.getByTestId("spdx3-band")).toContainText("Draft");
  await expect(page.getByRole("button", { name: "Fill in empty fields" })).toHaveCount(0);
});

const openFlow = async (page: Page) => {
  await page.getByRole("button", { name: "Fill in empty fields" }).click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow).toBeVisible();
  return flow;
};
const next = (flow: ReturnType<Page["getByTestId"]>) => flow.getByRole("button", { name: /^Next/ }).click();

test("list answers take more rows, and an empty row stays while it is typed in", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await next(flow);
  const author = flow.locator('[data-question="document.createdBy"]');
  await author.getByRole("textbox").first().fill("Acme AI Lab");
  await author.getByRole("button", { name: "Add another" }).click();
  await expect(author.getByRole("textbox")).toHaveCount(2);
  await author.getByRole("textbox").nth(1).fill("Partner Lab");
  await author.getByRole("textbox").nth(1).fill("");
  await expect(author.getByRole("textbox")).toHaveCount(2);
  await author.getByRole("textbox").nth(1).fill("Partner Lab");
  await flow.getByRole("button", { name: "Review" }).click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toContainText("Complete");
  expect((state.saved as { document: unknown }).document).toEqual({
    createdBy: [
      { type: "Organization", name: "Acme AI Lab" },
      { type: "Organization", name: "Partner Lab" },
    ],
  });
});

test("data the hub does not hold: an untouched one is dropped, a started one needs a name and an address", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await flow.getByRole("button", { name: "Training data" }).click();
  await flow.getByRole("button", { name: "Add data the hub does not hold" }).click();
  await flow.getByRole("button", { name: "Add data the hub does not hold" }).click();
  const locals = flow.locator('[data-dataset="local"]');
  await expect(locals).toHaveCount(2);
  await locals.nth(1).getByRole("button", { name: "Remove" }).click();
  await expect(locals).toHaveCount(1);
  await locals.first().getByLabel("Name").fill("Support logs 2025");
  await flow.getByRole("button", { name: "Review" }).click();
  await expect(flow.getByRole("button", { name: "Save" })).toBeDisabled();
  await expect(flow).toContainText("the server would refuse them");
  await flow.getByRole("button", { name: /Training data: / }).click();
  await locals.first().locator('[data-question="dataset.downloadLocation"] input').fill("https://data.example.com/logs");
  await flow.getByRole("button", { name: "Review" }).click();
  await expect(flow.getByRole("button", { name: "Save" })).toBeEnabled();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  expect((state.saved as { datasets: unknown[] }).datasets).toEqual([
    { local: "support-logs-2025", name: "Support logs 2025", downloadLocation: "https://data.example.com/logs" },
  ]);
});

test("a refused save shows the server's reasons and keeps the answers", async ({ page }) => {
  await stub(page, { refuse: ["model.releaseTime: a date must be written YYYY-MM-DDThh:mm:ssZ (UTC)"] });
  await openModels(page);
  const flow = await openFlow(page);
  await flow.getByRole("button", { name: "Review" }).click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(flow.getByRole("alert")).toContainText("The declaration was refused");
  await expect(flow.getByRole("alert")).toContainText("model.releaseTime");
  await expect(flow).toBeVisible();
});

test("a saved declaration is laid over the open fields when the questions reopen", async ({ page }) => {
  await stub(page, {
    saved: {
      schema: "bomlens-ai-declaration/1",
      model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/base", revision: "abc123" }] },
      datasets: [{ ref: "huggingface:org/ds", role: "testedOn" }],
    },
  });
  await openModels(page);
  const flow = await openFlow(page);
  await expect(flow.getByLabel("Revision (commit or tag, optional)")).toHaveValue("abc123");
  await next(flow);
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("2025-04-15");
  await next(flow);
  await expect(flow.getByRole("radio", { name: "Evaluation" })).toHaveAttribute("aria-checked", "true");
});

test("answers survive leaving the section; cancelling drops them and returns focus", async ({ page }) => {
  await stub(page);
  await openModels(page);
  let flow = await openFlow(page);
  await next(flow);
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await page.locator('a[href$="/components"]').first().click();
  await expect(page.getByTestId("ai-declaration")).toHaveCount(0);
  await page.locator('a[href$="/models"]').first().click();
  flow = page.getByTestId("ai-declaration");
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("2025-04-15");
  await flow.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Fill in empty fields" })).toBeFocused();
  flow = await openFlow(page);
  await next(flow);
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("");
});

test("single choices work from the keyboard as a radio group", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await next(flow);
  const scope = flow.locator('[data-question="model.weightsScope"]');
  await scope.getByRole("radio", { name: "Full weights" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(scope.getByRole("radio", { name: "Adapter only" })).toBeFocused();
  await expect(scope.getByRole("radio", { name: "Adapter only" })).toHaveAttribute("aria-checked", "true");
  await expect(scope.getByRole("radio", { name: "Full weights" })).toHaveAttribute("tabindex", "-1");
});

test("the questions have no accessibility violations", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  for (let i = 0; i < 4; i++) {
    const axe = await new AxeBuilder({ page }).include('[data-testid="ai-declaration"]')
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
    expect(axe.violations).toEqual([]);
    await next(flow);
  }
});

test("the artifact cards write the document and take a declaration file", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  await page.getByRole("navigation").locator('a[href$="/artifacts"]').first().click();
  await page.getByRole("button", { name: "Write SPDX 3.0.1" }).click();
  await expect.poll(() => state.exported).toBe(1);
  await page.locator('input[type="file"][accept*="json"]').setInputFiles({
    name: "decl.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ schema: "bomlens-ai-declaration/1", model: { releaseTime: "2025-04-15T00:00:00Z" } })),
  });
  await expect.poll(() => state.saved).toEqual({ schema: "bomlens-ai-declaration/1", model: { releaseTime: "2025-04-15T00:00:00Z" } });
});

test("filling a declared model's fields keeps the base models and datasets its declaration named", async ({ page }) => {
  const original = {
    schema: "bomlens-ai-declaration/1",
    model: { baseModels: [{ ref: "org/base", revision: "" }] },
    datasets: [{ ref: "huggingface:org/ds", role: "trainedOn" }],
  };
  const state = await stub(page, { declared: true, saved: original });
  await openModels(page);
  const flow = await openFlow(page);
  await flow.getByRole("button", { name: "Review" }).click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  const saved = state.saved as { model: { baseModels: unknown[] }; datasets: { ref?: string }[] };
  expect(saved.model.baseModels).toEqual([{ ref: "org/base", revision: "" }]);
  expect(saved.datasets.map((d) => d.ref)).toContain("huggingface:org/ds");
});
