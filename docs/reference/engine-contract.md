---
description: The result manifest (bomlens-result.json) every scan writes, for a program that runs the BomLens image as its scan engine.
---

# Engine contract

A program that runs the BomLens image as its scan engine reads `bomlens-result.json`, written to the output folder by every scan. It says how the run ended, which steps ran, were turned off, could not run or failed, and which file in the folder plays which role, so the program does not parse the log or guess file names.

The format is checked against [`schemas/engine-result-1.json`](https://github.com/sktelecom/bomlens/blob/main/schemas/engine-result-1.json) by `tests/test-engine-contract.sh` in CI. This page describes contract version `1.0.0`.

## The file

`bomlens-result.json` has a fixed name, so give each scan its own output folder. A manifest left in the folder by an earlier run is removed when the run starts, before anything else is checked, and the new one is written when the run ends, also when it stops early on an error. A folder with no manifest after the run means the engine was killed before it could write one.

The scan's exit code is unchanged by the contract. A run that produced its SBOM exits 0 even when a step failed along the way; the manifest is where that failure is reported.

| Field | Meaning |
|---|---|
| `contract` | `name` is `bomlens-engine`, `version` the contract version (semantic versioning, separate from the BomLens version) |
| `engine` | `version` is the BomLens version built into the image. `image` and `image_digest` repeat `BOMLENS_IMAGE_REF` and `BOMLENS_IMAGE_DIGEST` when the caller passes them; the image cannot see its own reference |
| `input` | `kind` (`source`, `image`, `sbom`, `binary`, `rootfs`, `firmware`, `ai-model`, `dataset`), the `MODE` it ran in, and `target` (the image reference for an image scan; paths are not recorded) |
| `run` | `status`, `reason`, `started_at`, `ended_at` (UTC), `exit_code` |
| `steps[]` | one entry per step, in the order they were recorded; a step is recorded when it ends (below) |
| `tools` | tool name and version: the generator recorded in the SBOM, syft, and Trivy when the vulnerability scan ran |
| `engines` | the vulnerability engines whose results this run produced (`trivy`, `grype`, `cve-bin-tool`, `yocto`) |
| `data_sources.trivy_db` | the Trivy database's schema version, `updated_at` and `downloaded_at`, when the vulnerability scan ran |
| `outputs[]` | `role`, `path` (relative to the output folder), `sha256` and `bytes` of each file the run wrote |

## Run status

| `run.status` | When |
|---|---|
| `succeeded` | exit code 0, and every recorded step `ok`, `disabled`, or `skipped` because it had nothing to read (`no_input`) |
| `succeeded_degraded` | exit code 0, and at least one step `failed` or `degraded`, or `skipped` for any other reason (a step that was asked for and could not run: its tool not installed, its input over a limit, its image unavailable). The SBOM is valid; read `steps[]` to decide whether the failed step matters to you |
| `failed` | the run exited with a non-zero code (`reason` is `exit_code`) |
| `cancelled` | the run was stopped by a signal (exit code 130 or 143) |

A failed vulnerability scan never yields `succeeded`. Trivy writes an empty result with a `ScanError` when its database cannot be read; the manifest reports that as `scan-security` `failed`, with Trivy's message in `detail`, so "no vulnerabilities" and "the scan did not run" stay apart.

## Steps

Every step that applies to the scan's mode is recorded, also when it did not run. A step that does not apply to the mode at all (CPE enrichment of an AI model) is left out.

| `status` | Meaning |
|---|---|
| `ok` | ran and completed |
| `degraded` | ran, but with less than it needed (for example, the offline end-of-life data was missing) |
| `failed` | ran and failed; the SBOM is still written. Most post-process steps also add their name to the SBOM's `bomlens:pipeline-step-failed` property; the manifest is the complete record |
| `skipped` | could not run: its tool is not in the image, or its input is missing |
| `disabled` | a setting turned it off |

<!-- reasons:begin -->
| `reason` | Meaning |
|---|---|
| `failed` | the step returned an error |
| `timeout` | the step ran out of time |
| `not_installed` | the tool it needs is not in this image |
| `too_large` | the input was over the step's size limit |
| `fallback` | a simpler method was used instead (the SBOM came from the manifest-only fallback, direct dependencies only), or the step ran without the image it needs (`--deep-license` when the scancode image could not be pulled) |
| `unavailable` | the data the step reads was not available |
| `budget_exhausted` | the step stopped at its work limit |
| `no_input` | there was nothing for the step to read (no source tree, no signing key) |
<!-- reasons:end -->

No step reports `budget_exhausted` yet; it is reserved for a work limit a later release records.

Each step also has `stage` (1 for the SBOM a language image generated before this container started, 2 otherwise), `started_at`, `ended_at`, an optional `detail` of up to 500 characters, and for some steps `counts` (`generate` records `components`).

<!-- steps:begin -->
| Step | What it does |
|---|---|
| `generate` | produce the SBOM (stage 1 for a source scan, where the language image ran first) |
| `vendored` | identify open source copied into the sources (`--identify-vendored`) |
| `suggest-vendored` | suggest that identification when a C/C++ project scanned near-empty |
| `cocoapods` | add CocoaPods dependencies from `Podfile.lock` |
| `stamp-metadata` | set the root component to the project name and version; the run stops if this fails |
| `docmeta` | record the document's author, tool and lifecycle phase |
| `license-registry` | ask the package registry for missing licences and check a single strong-copyleft or non-commercial one (`--license-registry`); `counts` gives `candidates`, `filled`, `superseded`, `confirmed`, `no_answer`, `not_found`, `non_standard`, `lookup_failed`, `budget_reached` |
| `normalize` | normalize licences, PURLs and duplicates |
| `enrich-cpe` | add CPE identifiers |
| `enrich-os-context` | record the operating system packages' distribution |
| `enrich-distro-supplier` | record the distribution as the OS packages' supplier |
| `enrich-maven-cpe` | add CPEs for Maven components |
| `enrich-github-cpe` | add CPEs for components named by GitHub repository |
| `enrich-interpreter-cpe` | add CPEs for language runtimes |
| `enrich-eol` | mark end-of-life versions (offline data) |
| `enrich-malicious` | mark known malicious packages (offline data) |
| `enrich-staleness` | measure how far behind each version is (opt-in, online) |
| `declared-sources` | apply the dataset sources an AI declaration names |
| `declared-service` | apply the AI service an AI declaration describes |
| `assess-ai-risk` | assess the AI model's risk |
| `resolve-purl` | look each PURL up in its package repository (`--resolve-purl`) |
| `describe-input` | record the supplier SBOM's own format and tool (`--analyze`) |
| `conformance` | check the SBOM against the minimum elements |
| `deep-license` | detect licences in the source files with scancode (`--deep-license`) |
| `source-file-tree` | record the scanned tree's file list |
| `source-snapshot` | keep the scanned files' content for the file viewer |
| `generate-notice` | write the open source notice |
| `scan-security` | match vulnerabilities with Trivy |
| `generate-risk-report` | write the risk report |
| `model-security` | check an AI model file for unsafe content |
| `verify-weights` | check that a model's published weights match their hashes |
| `enrich-aibom` | add details read from the model's hub page |
| `sign` | sign the SBOM with cosign (`--sign`) |
<!-- steps:end -->

## Output roles

| `role` | File |
|---|---|
| `sbom.cyclonedx` | `_bom.json` |
| `sbom.spdx` | `_bom.spdx.json` |
| `sbom.spdx3` | `_bom.spdx3.json` |
| `vulnerabilities.trivy` | Trivy's own result. This is `_security.json` when no other engine added results, and `_security_trivy.json` (Trivy's result kept apart before the merge) when one did |
| `vulnerabilities.all` | `_security.json`, Trivy's result with the other engines' results merged in |
| `vulnerabilities.other` | another engine's result (`_security_grype.json`, `_security_cvebintool.json`, `_security_yocto.json`) |
| `license-scan.scancode` | `_scancode.json` |
| `vendored.cyclonedx` | `_vendored.cdx.json` |
| `conformance` | `_conformance.json` |
| `input-description` | `_input.json` |
| `other` | any other file the run wrote (reports, sidecars) |

## Package identifiers

Operating system packages in `bom.json` carry PURLs in the form Trivy and the purl-spec use, so they join the same packages from a Trivy scan or a supplier SBOM:

- deb: the epoch is an `epoch` qualifier, not part of the version (`pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64&distro=debian-12&epoch=1`).
- apk: `distro` is the release id (`distro=3.20.10`).
- deb, rpm, apk: no `upstream` qualifier; the source package is in the `aquasecurity:trivy:SrcName` property (with `SrcVersion`, `SrcRelease`, `SrcEpoch`), which is what Trivy matches distribution advisories on.
- Qualifiers are sorted by name.

A change to this form is a major version change (see below).

## Versioning

The contract version changes on its own schedule, not with each BomLens release.

- Major: a field, step id, output role or status value is removed, renamed, or changes meaning, or a change makes the same input produce a different PURL or licence id, or reports a failure as success.
- Minor: a new optional field, step id, reason, output role or status detail. A reader ignores values it does not know.
- Patch: no change a reader can see in the fields above.

Properties named `bomlens:*` in the SBOM, and the human-readable reports, are not part of the contract and can change in any release.
