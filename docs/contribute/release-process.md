---
description: How a BomLens release actually gets cut, verified, and rolled back if something goes wrong.
---

# Release process

This describes the real release flow for `sktelecom/bomlens`, run from the
`haksungjang/bomlens` fork that development happens on. It assumes the
release commit (CHANGELOG + `electron/package.json` version bump) is already
on the fork's `main`.

## Checklist

1. **Sync the fork's `main` up to `sktelecom/bomlens`'s `main`**, so the
   release is cut from a commit the upstream org repository actually has.
2. **Dispatch `release-upstream.yml`** on the fork with the version (e.g.
   `v1.11.9`). This assembles the release on the fork's runners but keeps
   `sktelecom`'s signing identity: Sigstore builds the certificate subject
   from the called workflow's ref, not the caller's, by calling
   `docker-publish.yml` and `release.yml` from `sktelecom/bomlens@main`
   rather than copies. It needs `UPSTREAM_PUBLISH_TOKEN` (`contents:write` +
   `packages:write` on `sktelecom/bomlens`).
   - This one dispatch builds and signs all four images (the post-process
     image plus the firmware/AIBOM/deep-cve opt-in images), creates the
     draft release, uploads the CLI bundles and source SBOM, and only then
     runs `release-gate`, which polls for the installers and the published
     images, runs the documented first-scan command against the real
     published image, and only if all of that passes flips the release
     from draft to public.
   - A release that fails partway through stays a **draft** and is never
     shown to users. There is nothing to roll back for that case; fix the
     cause and re-dispatch (`run_images: false` skips the image build if it
     already succeeded; `run_installers: false` does the same for the
     desktop installers).
3. **Dispatch `demo-capture.yml`, then merge the PR it opens.** This
   workflow only re-scans the demo fixtures and pushes a branch with a pull
   request; it does not touch the live site by itself. Pass the new
   version as `image_tag` so the capture runs against the just-published
   image rather than whatever `latest` happens to be. Until that PR is
   merged to the fork's `main`, the demo data is still whatever it was
   before this release.
4. **Dispatch `publish-upstream-docs.yml`**, which calls `docs.yml` from
   `sktelecom/bomlens@main` to rebuild the MkDocs site (from the fork's own
   `docs/`, since that call carries no `repository:` override) and push it
   to that repository's `gh-pages` branch: a direct branch push, not a
   Pages artifact deploy, for the reason `docs.yml`'s own header comment
   gives. Doing this before step 3's PR is merged ships the old demo data.
5. **Verify all five channels** a user could hit: the GitHub release page,
   `docker pull` of the published images, the desktop installers, the demo
   site, and the docs site. `release-assets-verify.yml`'s weekly schedule
   only exercises the desktop installer downloads and their checksum
   signature; the release-page assets and the `docker pull` checks live in
   its `verify-release-full` job (also what `release-gate` above already
   ran once), which only runs on a manual dispatch naming a tag. The demo
   and docs sites have no automated post-deploy check yet; see below.

## Docs-site post-deploy verification

Nothing currently confirms the `gh-pages` push in step 4 actually reached
the live site. Until that is automated, check by hand after dispatching
`publish-upstream-docs.yml`: the site should serve the desktop installer
download link the release just published.

```bash
curl -fsSL https://sktelecom.github.io/bomlens/ | grep -c 'releases/latest/download/BomLens-Setup.exe'
```

A count of `0`, or the command failing outright, means the `gh-pages` push
did not land or Pages has not picked it up yet; check the `docs.yml` run's
logs before re-dispatching. This only proves the page rendered at all, not
that it reflects this specific version; there is no version string rendered
into the page today (only a shields.io badge image), so telling "this
release's docs" apart from "an older but still-working docs build" still
needs a look at the `gh-pages` branch's latest commit.

## Rollback

There is no single "undo" command; what to do depends on what already
shipped.

- **Release still a draft** (the common case: `release-gate` failed): fix
  the cause and re-dispatch `release-upstream.yml`. Nothing was ever shown
  to a user.
- **Release published, but an image is broken**: publish a new patch version
  with the fix rather than deleting or re-pointing a tag. A tag a user has
  already pulled by digest should keep meaning what it meant; a silently
  rewritten `vX.Y.Z` breaks that even if `latest` also moves forward. If the
  break is severe enough that the published version must not keep being
  installed, mark the GitHub release as `prerelease` (via `gh release edit`)
  so it stops being `/releases/latest` while the fix is prepared. Do not
  delete the release or its assets; that breaks anyone who already has the
  URL.
- **Desktop installers are broken but the images are fine**: dispatch
  `desktop.yml` directly (not `release-upstream.yml`, whose `release` job
  has no `if:` and would re-assemble and re-gate the whole release even
  with `run_images: false`) to re-attach corrected installers to the
  existing release.
- **Docs site shipped something wrong**: fix the source in `docs/`, then
  re-run `publish-upstream-docs.yml`. The `gh-pages` push is a full
  overwrite each time, with no history to revert, so a corrected source
  rebuild is the fix, not a git revert of `gh-pages` itself.

## Deferred findings

There is no dedicated backlog or label for this; it is meant to stay rare.
The working rule (see the project's own contribution norms) is that a
finding discovered while preparing a release gets fixed before that release
ships, not deferred with a note to come back to it. If something genuinely
cannot be fixed before a release and is not release-blocking on its own
merits, track it as a normal GitHub issue and reference it from the PR that
knowingly ships around it, rather than inventing a separate tracking
mechanism for it.
