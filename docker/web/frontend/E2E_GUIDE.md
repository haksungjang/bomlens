# E2E guide — web UI

How the frontend end-to-end tests are structured, how to run them, and how to
add new ones. The goal is that the team owns and extends this harness without
re-deriving the wiring each time.

## Two layers

| Layer | Dir | Backend | Runs in CI | What it proves |
| --- | --- | --- | --- | --- |
| Stubbed UI | `tests/ui` | `page.route` mocks | always (`test:ui`, `test:visual`) | the UI renders/behaves correctly for given API responses, deterministically, with no Docker or network |
| Real integration | `tests/integration` | a running BomLens container | opt-in | the upload → scan → results wiring actually works against `docker/web/server.py` |

The stubbed layer is fast and hermetic but, by construction, cannot catch a
break between the UI and the real server (a renamed endpoint, a changed SSE
shape). The integration layer closes exactly that gap on one happy path. Keep
most coverage in the stubbed layer; add an integration test only when a flow
must be proven against the real backend.

## Commands

```sh
npm run test:unit         # Vitest — pure data/display logic (src/**/*.test.ts)
npm run test:ui           # Playwright — functional + axe (stubbed, @capture/@visual excluded)
npm run test:visual       # Playwright — visual regression (@visual); see "Visual baselines"
npm run test:integration  # Playwright — real backend; needs BOMLENS_BASE_URL (see below)
npm run capture:ui        # Playwright — regenerate doc screenshots (@capture)
```

## Shared helpers (`tests/ui/helpers.ts`)

Stubbed specs declare only the scenario data; the wiring lives in one place.

- `stubBackend(page, opts)` — route the backend endpoints with `page.route`.
  Only the endpoints implied by `opts` are stubbed:
  - `caps` — capability flags, merged over `DEFAULT_CAPS` (`{ docker: true }`).
  - `results`, `done`, `file`, `scans`, `scanById`, `upload`, `streamDelayMs`.
  - `done` is the `/scan-stream` SSE payload; `streamDelayMs` delays it so the
    running view is observable.
- `openShell(page, theme?, lang?)` — open the redesigned shell (`?ui=next`) with
  theme/language seeded into `localStorage` before boot.
- `runScan(page, project, version)` — fill the project/version fields and start.
- `killAnim(page)` — disable animations for crisp element screenshots.

Example:

```ts
import { runScan, stubBackend } from "./helpers";

await stubBackend(page, { caps: { scanoss: true }, done: MY_DONE });
await page.goto("/?ui=next");
await runScan(page, "demo", "1.0");
```

Scenario fixtures (the `DONE`/`SBOM` objects) stay in each spec — they describe
what that test exercises and should not be hoisted into the shared module.

## Selector rules

- Prefer `getByRole` and `getByText`. There are **no `data-testid` hooks**; tests
  bind to the accessible name/role, which keeps them honest about a11y and
  resilient to markup churn.
- Never use CSS `nth`/class selectors for behavioural assertions.
- Integration tests run against whatever language the container serves (Korean
  by default), so select language-independently — `getByPlaceholder("my-app")`,
  or a name regex that matches both locales (`/Run scan|스캔 실행/`).

## Adding a stubbed UI test

1. Put scenario data (the `done`/`file` payload) at the top of the spec.
2. `await stubBackend(page, { ... })`, then `openShell`/`goto`, then `runScan`.
3. Assert via roles/text. Add an axe check for any new view:
   `expect((await new AxeBuilder({ page }).withTags([...]).analyze()).violations).toEqual([])`.
4. `npm run typecheck && npm run test:ui`.

## Visual baselines

`@visual` snapshots are platform-dependent, so they are generated and compared
in the pinned Playwright container (`mcr.microsoft.com/playwright:v1.49.1-jammy`),
matching CI. To seed or refresh locally:

```sh
docker run --rm -v "$PWD:/work" -w /work \
  mcr.microsoft.com/playwright:v1.49.1-jammy \
  bash -lc 'npm ci && npm run test:visual -- --update-snapshots'
```

Commit the PNGs under `tests/ui/*-snapshots/`; CI then runs a strict diff.

## Real-backend integration

The integration suite (`playwright.integration.config.ts`) has no `webServer`
and no stubs — it drives the SPA served by a running container and points at it
via `BOMLENS_BASE_URL`. A deterministic fixture
(`tests/integration/fixtures/sample-src`) carries manifests syft resolves
offline, so a `current-dir` scan always yields a non-empty SBOM.

```sh
# 1. Start a container with the fixture mounted at /src.
docker run --rm -d --name bomlens-integration -p 8095:8080 \
  -v "$PWD/tests/integration/fixtures/sample-src":/src:ro \
  -v "$(mktemp -d)":/host-output \
  -e MODE=UI -e UI_PORT=8080 \
  ghcr.io/sktelecom/sbom-scanner:latest

# 2. Run the integration tests against it.
BOMLENS_BASE_URL=http://localhost:8095 npm run test:integration

# 3. Tear down.
docker rm -f bomlens-integration
```

Notes:
- The test asserts the Components count is `> 0`, not an exact number, so it
  stays robust across scanner versions.
- It targets the dist baked into the image. To exercise the latest frontend
  against the real backend, build the image from this checkout first.
- These tests need Docker and the image, so they are opt-in and excluded from
  the default `test:ui`/unit/visual CI jobs.

## CI mapping

- `ui` job → `typecheck`, `token:lint`, `i18n:check`, `test:unit`, `test:ui`.
- `visual` job → `test:visual` in the pinned container (seed-then-strict-diff).
- Integration is intentionally not wired into the default PR run; gate it behind
  a label or a manual workflow if/when the team wants it in CI.
