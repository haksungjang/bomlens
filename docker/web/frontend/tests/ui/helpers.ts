import { type Page } from "@playwright/test";

/**
 * Shared E2E helpers for the web UI specs.
 *
 * Every spec used to inline its own `stub()` that wired up page.route for the
 * same handful of endpoints (/capabilities, /results, /scan-stream, /file,
 * /scans, /scan), drifting apart over time. This module owns that wiring once so
 * specs only declare the scenario data they care about. See E2E_GUIDE.md.
 *
 * These helpers stub the backend (page.route) for deterministic, Docker-free UI
 * tests. The real-backend path is covered separately by tests/integration
 * (see playwright.integration.config.ts).
 */

export type Theme = "light" | "dark";
export type Lang = "en" | "ko";

export type Caps = {
  firmware: boolean;
  scanoss: boolean;
  docker: boolean;
  aibom?: boolean;
};

// A plain source scan host: Docker present, no scanoss/firmware/aibom add-ons.
// Specs override only the capability they exercise (e.g. { scanoss: true }).
export const DEFAULT_CAPS: Caps = { firmware: false, scanoss: false, docker: true };

export type UploadResult =
  | { token: string; filename: string }
  | { status: number; error: string };

export interface StubOptions {
  /** Capability flags; merged over DEFAULT_CAPS. */
  caps?: Partial<Caps>;
  /** GET /results payload (prior artifacts). Defaults to []. */
  results?: unknown[];
  /** POST /upload response — a token (success) or { status, error } (failure). */
  upload?: UploadResult;
  /** `done` event payload for the GET /scan-stream SSE. Omit to leave it unrouted. */
  done?: unknown;
  /** Delay before the stream fulfils, to observe the running view. */
  streamDelayMs?: number;
  /** GET /file payload (the raw SBOM the dependency/source views read). */
  file?: unknown;
  /** GET /scans payload (the rail's Recent list). */
  scans?: unknown[];
  /** GET /scan?id=<id> payloads, keyed by scan id (re-opening a past scan). */
  scanById?: Record<string, unknown>;
}

function json(body: unknown) {
  return { contentType: "application/json", body: JSON.stringify(body) };
}

/**
 * Stub the backend API for a deterministic UI test. Only the endpoints implied
 * by `opts` are routed, so a spec can stub just what it needs.
 */
export async function stubBackend(page: Page, opts: StubOptions = {}): Promise<void> {
  const caps: Caps = { ...DEFAULT_CAPS, ...(opts.caps ?? {}) };
  await page.route("**/capabilities", (r) => r.fulfill(json(caps)));
  await page.route("**/results", (r) => r.fulfill(json(opts.results ?? [])));

  if (opts.upload) {
    const u = opts.upload;
    await page.route("**/upload**", (r) =>
      "token" in u
        ? r.fulfill(json(u))
        : r.fulfill({ status: u.status, ...json({ error: u.error }) }),
    );
  }

  if (opts.done !== undefined) {
    // EventSource stream: a single `done` event then close — the app treats a
    // close after `done` as success (see api.ts onerror/finished).
    const body = `event: done\ndata: ${JSON.stringify(opts.done)}\n\n`;
    await page.route("**/scan-stream**", async (r) => {
      if (opts.streamDelayMs) await new Promise((res) => setTimeout(res, opts.streamDelayMs));
      await r.fulfill({ contentType: "text/event-stream", body });
    });
  }

  if (opts.file !== undefined) {
    await page.route("**/file**", (r) => r.fulfill(json(opts.file)));
  }

  if (opts.scans !== undefined) {
    await page.route("**/scans", (r) => r.fulfill(json(opts.scans)));
  }

  if (opts.scanById) {
    for (const [id, payload] of Object.entries(opts.scanById)) {
      await page.route(`**/scan?id=${id}`, (r) => r.fulfill(json(payload)));
    }
  }
}

/**
 * Open the redesigned shell (`?ui=next`) with theme + language seeded into
 * localStorage before the app boots, so each combination renders deterministically.
 */
export async function openShell(page: Page, theme: Theme = "light", lang: Lang = "en"): Promise<void> {
  await page.addInitScript(
    ([t, l]) => {
      localStorage.setItem("sbom.theme", t);
      localStorage.setItem("sbom.lang", l);
    },
    [theme, lang],
  );
  await page.goto("/?ui=next");
  await page.getByRole("navigation").first().waitFor();
}

/** Fill the project/version fields and start the scan. */
export async function runScan(page: Page, project: string, version: string): Promise<void> {
  await page.fill("#project", project);
  await page.fill("#version", version);
  await page.getByRole("button", { name: /Run scan/i }).click();
}

/** Disable animations/transitions so element screenshots are crisp and stable. */
export async function killAnim(page: Page): Promise<void> {
  await page.addStyleTag({
    content: "*,*::before,*::after{animation:none!important;transition:none!important;opacity:1!important}",
  });
}
