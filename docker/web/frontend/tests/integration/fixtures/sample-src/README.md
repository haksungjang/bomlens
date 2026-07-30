# sample-src — integration fixture

A tiny, deterministic source tree mounted at `/src` for the real-backend
integration test (`tests/integration/scan.spec.ts`). It carries manifests syft
can resolve without a network or Docker socket, so a `current-dir` scan always
produces a non-empty SBOM:

- `package-lock.json` — one npm dependency (`left-pad`).
- `requirements.txt` — two pinned Python dependencies (`flask`, `click`).

Keep at least one resolvable component here; the test asserts the Components
count is greater than zero. See `../../../E2E_GUIDE.md`.
