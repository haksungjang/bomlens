import { defineConfig, devices } from "@playwright/test";

// Real-backend integration tests: drive the SPA served by a running BomLens
// container (docker/web/server.py) and exercise an actual scan end to end — no
// page.route stubs. This covers the upload/scan-stream/results wiring against the
// real server, the gap the stubbed tests/ui suite cannot reach.
//
// Opt-in: these need Docker + the bomlens image, so they live outside the default
// `test:ui` run and the unit/visual CI jobs. Point BOMLENS_BASE_URL at a running
// container; see E2E_GUIDE.md "Real-backend integration" for how to start one.
const baseURL = process.env.BOMLENS_BASE_URL ?? "http://localhost:8080";

export default defineConfig({
  testDir: "./tests/integration",
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  // A real scan is far slower than a stubbed render; allow generous time.
  timeout: 240_000,
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
