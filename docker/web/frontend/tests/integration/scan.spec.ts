import { expect, test } from "@playwright/test";

/**
 * Real-backend integration: NO page.route stubs. Drives the SPA served by a
 * running BomLens container and runs an actual current-folder scan, proving the
 * capabilities/scan-stream/results wiring works against docker/web/server.py —
 * the gap the stubbed tests/ui suite cannot cover.
 *
 * Requires a running container with BOMLENS_BASE_URL pointing at it. Start one as
 * described in E2E_GUIDE.md ("Real-backend integration"), then:
 *   BOMLENS_BASE_URL=http://localhost:8095 npm run test:integration
 */
test.describe("@integration real scan against a running BomLens container", () => {
  test("capabilities endpoint responds from the real server", async ({ request, baseURL }) => {
    const res = await request.get(`${baseURL}/capabilities`);
    expect(res.ok()).toBeTruthy();
    const caps = await res.json();
    // The real server reports concrete capability booleans (probed from the
    // container), unlike the fixed object the stubbed suite injects.
    expect(typeof caps.firmware).toBe("boolean");
    expect(typeof caps.docker).toBe("boolean");
  });

  test("current-folder scan runs and renders real components", async ({ page }) => {
    // Drives whichever UI the running container serves (the classic form on the
    // v1.3.0 image). Placeholder/role selectors keep this independent of the UI
    // language (the container defaults to Korean). Current folder is the default
    // source, so just name the project and run.
    await page.goto("/");
    await page.getByPlaceholder("my-app").fill("integration");
    await page.getByPlaceholder("1.0.0").fill("e2e");
    await page.getByRole("button", { name: /Run scan|스캔 실행/ }).click();

    // The real scan streams logs, then completes. A real syft+trivy run is far
    // slower than a stubbed render, so allow generous time.
    await expect(page.getByText(/Scan complete|스캔 완료/)).toBeVisible({ timeout: 180_000 });

    // Real components were produced by the scan (the sample-src fixture resolves
    // to ≥1): open the Components tab and assert the table has rows.
    await page.getByRole("tab", { name: /Components|컴포넌트/ }).click();
    const rows = page.locator("table tbody tr");
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeGreaterThan(0);
  });
});
