#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-engine-contract.sh - the engine contract (docs/reference/engine-contract.md).
#
# Runs docker/entrypoint.sh from this checkout (BOMLENS_LIBDIR points it at
# docker/lib), no Docker, and checks bomlens-result.json: it validates against
# schemas/engine-result-1.json, it is written when a run stops early, every step
# id is one the contract documents, and a Trivy failure is reported as a failed
# step and never as a successful run. That last check is shown to be able to
# fail: it is run once more against a copy of the scripts with the ScanError
# rule removed, and must then report the failure as hidden.
#
# Trivy is replaced by a stub on PATH, so the result does not depend on a
# vulnerability database or the network. Needs bash 4+, jq and python3;
# the full JSON Schema check also needs the jsonschema package.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRY="$ROOT_DIR/docker/entrypoint.sh"
SCHEMA="$ROOT_DIR/schemas/engine-result-1.json"
DOC="$ROOT_DIR/docs/reference/engine-contract.md"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[ERROR] bash 4 or later is required (this is $BASH_VERSION)"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Trivy stub ---------------------------------------------------------------
# TRIVY_STUB=ok writes a report with one finding; TRIVY_STUB=fail exits 1 with
# a database error on stderr, the way a missing or unreachable DB does.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/trivy" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "version" ]; then
    echo '{"Version":"0.0.0-stub","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-01-01T00:00:00Z","DownloadedAt":"2026-01-01T01:00:00Z"}}'
    exit 0
fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac
done
if [ "${TRIVY_STUB:-ok}" = "sleep" ]; then
    : > "$TRIVY_STUB_STARTED"
    sleep 3
fi
if [ "${TRIVY_STUB:-ok}" = "fail" ]; then
    echo "FATAL	failed to download vulnerability DB: stub error" >&2
    exit 1
fi
cat > "$out" <<'JSON'
{"SchemaVersion":2,"Results":[{"Target":"bom","Type":"npm","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20",
  "PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.20"},"Severity":"HIGH","FixedVersion":"4.17.21"}]}]}
JSON
EOF
chmod +x "$WORK/bin/trivy"

# run_engine <dir> <libdir> [VAR=value ...] - a CLI-style POSTPROCESS run.
run_engine() {
    local dir="$1" lib="$2"; shift 2
    ( cd "$dir" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
        HOST_OUTPUT_DIR="$dir" BOMLENS_LIBDIR="$lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
        UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
        ENRICH_EOL=false ENRICH_MALICIOUS=false "$@" bash "$ENTRY" ) > "$dir.log" 2>&1
}

new_run() {
    local d="$WORK/$1"
    mkdir -p "$d"
    [ "${2:-}" = "empty" ] || cp "$FIX/good-cyclonedx.json" "$d/demo_1.0_bom.json"
    printf '%s' "$d"
}

# The one rule a consumer depends on most: a Trivy run that failed is a failed
# step, and the run is never reported as a plain success. Prints what is wrong.
trivy_failure_violation() {
    jq -r '
        ([.steps[] | select(.id == "scan-security")] | first) as $s
        | if $s == null then "no scan-security step"
          elif $s.status != "failed" then "scan-security is \($s.status), not failed"
          elif .run.status == "succeeded" then "run.status is succeeded"
          else empty end' "$1" 2>/dev/null || echo "manifest unreadable"
}

JSPY=""
for py in python3 python3.13 python3.12 python3.11; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c "import jsonschema" 2>/dev/null; then JSPY="$py"; break; fi
done
schema_errors() {
    [ -n "$JSPY" ] || return 0
    "$JSPY" - "$SCHEMA" "$1" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:10]))
PY
}

# Step ids and reasons the contract documents: the backticked first column of
# the step table, and the reason table, in docs/reference/engine-contract.md.
DOC_STEPS="$(sed -n '/^<!-- steps:begin -->/,/^<!-- steps:end -->/p' "$DOC" | grep -oE '^\| `[a-z0-9-]+`' | tr -d '|` ')"
DOC_REASONS="$(sed -n '/^<!-- reasons:begin -->/,/^<!-- reasons:end -->/p' "$DOC" | grep -oE '^\| `[a-z_]+`' | tr -d '|` ')"
vocab_violations() {
    local id out=""
    for id in $(jq -r '.steps[].id' "$1"); do
        printf '%s\n' "$DOC_STEPS" | grep -qx "$id" || out="$out step:$id"
    done
    for id in $(jq -r '.steps[].reason // empty' "$1"); do
        printf '%s\n' "$DOC_REASONS" | grep -qx "$id" || out="$out reason:$id"
    done
    printf '%s' "${out# }"
}

echo "== a successful run =="
OK="$(new_run ok)"
run_engine "$OK" "$ROOT_DIR/docker/lib"
rc=$?
M="$OK/bomlens-result.json"
[ "$rc" = 0 ] && pass "the run exits 0" || fail "the run exited $rc" "$(tail -5 "$OK.log")"
[ -f "$M" ] && pass "bomlens-result.json is written" || fail "no bomlens-result.json"
err="$(schema_errors "$M")"
if [ -z "$JSPY" ]; then
    echo "  SKIP: jsonschema is not installed; the field checks below still run"
else
    [ -z "$err" ] && pass "the manifest validates against schemas/engine-result-1.json" || fail "schema errors" "$err"
fi
[ "$(jq -r '.contract.name + " " + .run.status + " " + (.run.exit_code|tostring)' "$M")" = "bomlens-engine succeeded 0" ] \
    && pass "contract name, run status succeeded, exit code 0" \
    || fail "run summary is $(jq -c '[.contract, .run.status, .run.exit_code]' "$M")"
n_fix="$(jq '[.components[]?] | length' "$FIX/good-cyclonedx.json")"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.stage) \(.counts.components)"' "$M")" = "ok 1 $n_fix" ] \
    && pass "generate is a stage-1 step with the component count" \
    || fail "generate step is $(jq -c '[.steps[] | select(.id=="generate")]' "$M")"
[ "$(jq -r '[.steps[] | select(.id=="scan-security")][0].status' "$M")" = "ok" ] \
    && pass "scan-security is ok" || fail "scan-security is $(jq -c '[.steps[] | select(.id=="scan-security")]' "$M")"
for id in generate-notice sign enrich-eol enrich-malicious enrich-staleness; do
    st="$(jq -r --arg id "$id" '[.steps[] | select(.id==$id)][0].status // "missing"' "$M")"
    [ "$st" = "disabled" ] && pass "$id, turned off by a setting, is recorded as disabled" \
        || fail "$id is $st, expected disabled"
done
[ "$(jq -r '[.outputs[] | select(.role=="vulnerabilities.trivy")][0].path' "$M")" = "demo_1.0_security.json" ] \
    && pass "with no other engine, vulnerabilities.trivy is _security.json" \
    || fail "vulnerabilities.trivy is $(jq -c '[.outputs[] | select(.role=="vulnerabilities.trivy")]' "$M")"
[ "$(jq -c '.engines' "$M")" = '["trivy"]' ] && pass "engines lists trivy only" || fail "engines is $(jq -c .engines "$M")"
[ "$(jq -r '.data_sources.trivy_db.updated_at' "$M")" = "2026-01-01T00:00:00Z" ] \
    && pass "the Trivy database date is recorded" || fail "trivy_db is $(jq -c .data_sources "$M")"
bom_sha="$(jq -r '[.outputs[] | select(.role=="sbom.cyclonedx")][0].sha256' "$M")"
real_sha="$( (sha256sum "$OK/demo_1.0_bom.json" 2>/dev/null || shasum -a 256 "$OK/demo_1.0_bom.json") | cut -d' ' -f1)"
[ "$bom_sha" = "$real_sha" ] && pass "the SBOM output's sha256 matches the file" || fail "sha256 $bom_sha != $real_sha"
v="$(vocab_violations "$M")"
[ -z "$v" ] && pass "every step id and reason is in the contract document" || fail "undocumented:" "$v"
[ -n "$(trivy_failure_violation "$M")" ] \
    && pass "negative control: the Trivy-failure check reports a violation on a successful run" \
    || fail "the Trivy-failure check passed a run whose Trivy succeeded; it cannot fail"

echo "== Trivy fails (injected) =="
TF="$(new_run trivy-fail)"
run_engine "$TF" "$ROOT_DIR/docker/lib" TRIVY_STUB=fail
rc=$?
M="$TF/bomlens-result.json"
[ "$rc" = 0 ] && pass "the exit code is unchanged (0): the manifest carries the failure" || fail "the run exited $rc"
v="$(trivy_failure_violation "$M")"
[ -z "$v" ] && pass "scan-security is failed and the run is not succeeded" || fail "Trivy failure hidden: $v"
[ "$(jq -r '.run.status' "$M")" = "succeeded_degraded" ] && pass "run.status is succeeded_degraded" \
    || fail "run.status is $(jq -r .run.status "$M")"
jq -r '[.steps[] | select(.id=="scan-security")][0].detail' "$M" | grep -q "stub error" \
    && pass "the step detail carries Trivy's own message" || fail "detail is $(jq -c '[.steps[] | select(.id=="scan-security")][0].detail' "$M")"
err="$(schema_errors "$M")"
[ -z "$err" ] && pass "the failure manifest validates against the schema" || fail "schema errors" "$err"

echo "== the Trivy-failure check fails when the rule is removed =="
MUT="$WORK/lib-mutant"
cp -R "$ROOT_DIR/docker/lib" "$MUT"
# Turn off the rule that makes a ScanError a failed step, leaving the rest of
# the jq program intact, so the copy still writes a manifest.
sed -i.bak 's/and \$scanerr != ""/and false/' "$MUT/engine-result.sh"
if grep -q 'scanerr != ""' "$MUT/engine-result.sh"; then
    fail "could not remove the ScanError rule from the copy (did its text change?)"
else
    MR="$(new_run mutant)"
    run_engine "$MR" "$MUT" TRIVY_STUB=fail
    v="$(trivy_failure_violation "$MR/bomlens-result.json")"
    # Exactly this violation: a missing or unreadable manifest would also be
    # non-empty, and would not show that the rule is what the check tests.
    [ "$v" = "scan-security is ok, not failed" ] && pass "without the rule the check reports the hidden failure ($v)" \
        || fail "the check still passes without the ScanError rule; it does not test it"
fi

echo "== a run that stops early still writes the manifest =="
EA="$(new_run early empty)"
echo '{"stale":true}' > "$EA/bomlens-result.json"
run_engine "$EA" "$ROOT_DIR/docker/lib"
rc=$?
M="$EA/bomlens-result.json"
[ "$rc" != 0 ] && pass "the run fails (no SBOM to post-process)" || fail "the run exited 0"
[ "$(jq -r '.run.status + " " + (.run.exit_code|tostring)' "$M" 2>/dev/null)" = "failed $rc" ] \
    && pass "the manifest is this run's, with run.status failed and the exit code" \
    || fail "manifest is $(cat "$M" 2>/dev/null | head -c 200)"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.stage)"' "$M" 2>/dev/null)" = "failed 1" ] \
    && pass "the step it stopped in (generate) is recorded as failed" \
    || fail "generate is $(jq -c '[.steps[] | select(.id=="generate")]' "$M" 2>/dev/null)"
err="$(schema_errors "$M")"
[ -z "$err" ] && pass "the early-failure manifest validates against the schema" || fail "schema errors" "$err"

echo "== a run that stops before the project is known replaces the old manifest =="
NP="$(new_run no-project)"
cp "$OK/bomlens-result.json" "$NP/bomlens-result.json"
run_engine "$NP" "$ROOT_DIR/docker/lib" PROJECT_VERSION=
rc=$?
[ "$rc" != 0 ] && [ "$(jq -r '.run.status' "$NP/bomlens-result.json" 2>/dev/null)" = "failed" ] \
    && pass "a missing PROJECT_VERSION leaves a failed manifest, not the previous run's success" \
    || fail "rc=$rc, manifest run.status is $(jq -r '.run.status' "$NP/bomlens-result.json" 2>/dev/null)"

echo "== metadata.tools in the CycloneDX 1.4 array form =="
TA="$(new_run tools-array)"
jq '.metadata.tools = [{"vendor":"x","name":"cdxgen","version":"9.0.0"}]' "$FIX/good-cyclonedx.json" > "$TA/demo_1.0_bom.json"
run_engine "$TA" "$ROOT_DIR/docker/lib"
rc=$?
[ "$rc" = 0 ] && pass "the run still exits 0" || fail "the run exited $rc"
[ "$(jq -r '.tools.cdxgen' "$TA/bomlens-result.json" 2>/dev/null)" = "9.0.0" ] \
    && pass "the manifest is written and reads the generator from the array form" \
    || fail "tools is $(jq -c .tools "$TA/bomlens-result.json" 2>/dev/null)"

echo "== a run stopped by TERM is recorded as cancelled =="
CN="$(new_run cancel)"
( cd "$CN" && exec env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$CN" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
    UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false TRIVY_STUB=sleep TRIVY_STUB_STARTED="$WORK/stub-started" \
    bash "$ENTRY" ) > "$CN.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do [ -f "$WORK/stub-started" ] && break; sleep 0.1; done
kill -TERM "$pid" 2>/dev/null
wait "$pid"
rc=$?
[ "$rc" = 143 ] && pass "the run exits 143" || fail "the run exited $rc"
[ "$(jq -r '.run.status + " " + (.run.exit_code|tostring)' "$CN/bomlens-result.json" 2>/dev/null)" = "cancelled 143" ] \
    && pass "run.status is cancelled with exit code 143" \
    || fail "manifest run is $(jq -c .run "$CN/bomlens-result.json" 2>/dev/null)"

echo "== deep-license: disabled, not installed, no input, too large, timeout, ok =="
SRCT="$WORK/srctree"
mkdir -p "$SRCT/lib" "$SRCT/node_modules/dep"
printf 'MIT License\n' > "$SRCT/LICENSE"
printf 'x\n' > "$SRCT/lib/a.c"
printf 'x\n' > "$SRCT/lib/b.c"
printf 'x\n' > "$SRCT/node_modules/dep/index.js"
# Matched without regard to case, like scancode does: not counted either.
mkdir -p "$SRCT/Vendor"; printf 'x\n' > "$SRCT/Vendor/v.c"
cat > "$WORK/bin/scancode-stub" <<'EOF2'
#!/bin/bash
# Records its arguments and writes a minimal result; sleeps when asked.
printf '%s\n' "$@" > "$SCANCODE_STUB_ARGS"
out=""
while [ $# -gt 0 ]; do case "$1" in --json-pp) out="$2"; shift 2 ;; *) shift ;; esac; done
# A partial result first, as a scan that is stopped midway leaves behind.
echo '{"files":[' > "$out"
[ -n "${SCANCODE_STUB_SLEEP:-}" ] && sleep "$SCANCODE_STUB_SLEEP"
echo '{"files":[{"path":"LICENSE","type":"file"}]}' > "$out"
exit "${SCANCODE_STUB_RC:-0}"
EOF2
chmod +x "$WORK/bin/scancode-stub"
dl_step() { jq -r '[.steps[] | select(.id=="deep-license")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }

D="$(new_run dl-off)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT"
[ "$(dl_step "$D")" = "disabled null" ] && pass "without --deep-license the step is disabled" || fail "deep-license is $(dl_step "$D")"

D="$(new_run dl-missing)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode
[ "$(dl_step "$D")" = "skipped not_installed" ] && pass "requested on an image without scancode: skipped, not_installed" || fail "deep-license is $(dl_step "$D")"

[ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded_degraded" ] \
    && pass "a requested step that could not run makes the run succeeded_degraded, not succeeded" \
    || fail "run.status is $(jq -r .run.status "$D/bomlens-result.json") with deep-license skipped/not_installed"

D="$(new_run dl-fallback)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode BOMLENS_DEEP_LICENSE_FALLBACK=ghcr.io/example/bomlens-deep-license:latest
[ "$(dl_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped fallback succeeded_degraded" ] \
    && pass "the CLI fell back to the base image: skipped, fallback, and the run is succeeded_degraded" \
    || fail "deep-license is $(dl_step "$D"), run.status $(jq -r .run.status "$D/bomlens-result.json")"
# The same check against a copy whose run-status rule ignores skipped steps
# must fail: the assertion above is what catches "no detection, still a pass".
MUT2="$WORK/lib-mutant-skipped"
cp -R "$ROOT_DIR/docker/lib" "$MUT2"
sed -i.bak 's/or (.status == "skipped" and .reason != "no_input")//' "$MUT2/engine-result.sh"
if grep -q 'reason != "no_input"' "$MUT2/engine-result.sh"; then
    fail "could not remove the skipped rule from the copy (did its text change?)"
else
    D="$(new_run dl-fallback-mutant)"; run_engine "$D" "$MUT2" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode BOMLENS_DEEP_LICENSE_FALLBACK=x
    [ "$(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)" = "succeeded" ] \
        && pass "without that rule the same run reads succeeded, so the check above can fail" \
        || fail "the mutant run is $(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null); the check does not isolate the rule"
fi

D="$(new_run dl-noinput)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$WORK/no-such-tree" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub"
[ "$(dl_step "$D")" = "skipped no_input" ] && pass "no source tree: skipped, no_input" || fail "deep-license is $(dl_step "$D")"
[ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded" ] && pass "nothing to read (no_input) leaves the run succeeded" \
    || fail "run.status is $(jq -r .run.status "$D/bomlens-result.json") with only a no_input skip"

D="$(new_run dl-large)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-large" DEEP_LICENSE_MAX_FILES=2
[ "$(dl_step "$D")" = "skipped too_large" ] && pass "three own files over a limit of two: skipped, too_large" || fail "deep-license is $(dl_step "$D")"
[ ! -f "$WORK/args-large" ] && pass "scancode is not started for a tree over the limit" || fail "scancode ran on a tree over the limit"

D="$(new_run dl-ok)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-ok" DEEP_LICENSE_MAX_FILES=3
[ "$(dl_step "$D")" = "ok null" ] && pass "three own files at a limit of three (node_modules not counted): ok" || fail "deep-license is $(dl_step "$D")"
[ "$(jq -r '[.outputs[] | select(.role=="license-scan.scancode")][0].path' "$D/bomlens-result.json")" = "demo_1.0_scancode.json" ] \
    && pass "_scancode.json is listed as license-scan.scancode" || fail "outputs: $(jq -c '[.outputs[].role]' "$D/bomlens-result.json")"
grep -qx 'node_modules' "$WORK/args-ok" && pass "scancode is told to ignore node_modules" || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"
grep -q '^/tmp/scancode.json$' "$WORK/args-ok" && fail "scancode still writes the fixed /tmp/scancode.json" || pass "scancode writes to a per-run temporary file"
grep -qx -- '--strip-root' "$WORK/args-ok" && [ "$(tail -n 1 "$WORK/args-ok")" = "$(cd "$SRCT" && pwd)" ] \
    && pass "scancode reads the tree itself, with --strip-root" \
    || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"
grep -qx 'demo_1.0' "$WORK/args-ok" && pass "this run's own output folder is left out" || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"

DIST="$WORK/dist"; mkdir -p "$DIST/src"; printf 'x\n' > "$DIST/src/a.c"
D="$(new_run dl-distroot)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DIST" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-dist"
! grep -qx 'dist' "$WORK/args-dist" && grep -qx 'node_modules' "$WORK/args-dist" \
    && pass "a tree whose own folder is named dist: dist is not ignored, the other names still are" \
    || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-dist")"

D="$(new_run dl-errors)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-err" SCANCODE_STUB_RC=1
[ "$(dl_step "$D")" = "degraded failed" ] && [ -s "$D/demo_1.0_scancode.json" ] \
    && pass "scancode errors on some files: the result is kept and the step is degraded" \
    || fail "deep-license is $(dl_step "$D"), _scancode.json present: $([ -f "$D/demo_1.0_scancode.json" ] && echo yes || echo no)"

D="$(new_run dl-broken)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-broken" SCANCODE_STUB_RC=2
[ "$(dl_step "$D")" = "failed failed" ] && [ ! -f "$D/demo_1.0_scancode.json" ] \
    && pass "scancode failing outright: failed, no result kept" || fail "deep-license is $(dl_step "$D")"

D="$(new_run dl-notsource)"; run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$FIX/good-cyclonedx.json" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub"
[ "$(dl_step "$D")" = "skipped no_input" ] && pass "asked for outside a source scan: skipped, no_input" || fail "deep-license is $(dl_step "$D")"

if command -v timeout >/dev/null 2>&1; then
    D="$(new_run dl-timeout)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-to" SCANCODE_STUB_SLEEP=5 DEEP_LICENSE_TIMEOUT=1
    [ "$(dl_step "$D")" = "failed timeout" ] && pass "scancode over its time limit: failed, timeout" || fail "deep-license is $(dl_step "$D")"
    [ ! -f "$D/demo_1.0_scancode.json" ] && pass "a stopped scan leaves no partial _scancode.json" || fail "a partial _scancode.json was kept"
    [ -s "$WORK/args-to" ] && pass "(scancode had started and written part of its result)" || fail "the stub never ran"
else
    echo "  SKIP: no timeout command on this host"
fi

echo "== license-registry: fill, replace, confirm, no answer, lookup failed (fixtures, no network) =="
LRF="$WORK/lr-fixtures"
mkdir -p "$LRF"
echo '{"licenses":["MIT"]}' > "$LRF/npm_lodash_4.17.21.json"
echo '{"licenses":["MIT"]}' > "$LRF/maven_org.slf4j_slf4j-api_2.0.13.json"
echo '{"licenses":["GPL-3.0-only"]}' > "$LRF/pypi_gplpkg_1.0.json"
cat > "$WORK/lr-bom.json" <<'EOF2'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"demo","version":"1.0","bom-ref":"root"}},
 "components":[
  {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","bom-ref":"a"},
  {"type":"library","name":"slf4j-api","version":"2.0.13","purl":"pkg:maven/org.slf4j/slf4j-api@2.0.13","bom-ref":"b","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"mysql-connector-java","version":"8.0.33","purl":"pkg:maven/mysql/mysql-connector-java@8.0.33","bom-ref":"c","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"gplpkg","version":"1.0","purl":"pkg:pypi/gplpkg@1.0","bom-ref":"d","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
  {"type":"library","name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0","bom-ref":"e","licenses":[{"license":{"id":"Apache-2.0"}}]}
 ]}
EOF2
lic() { jq -r --arg n "$2" '[.components[] | select(.name==$n)][0] | [(.licenses[]? | .expression // .license.id), ((.properties // []) | map(select(.name=="bomlens:license:superseded"))[0].value // "-")] | join(" ")' "$1/demo_1.0_bom.json"; }

D="$(new_run lr-off)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"; run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0].status' "$D/bomlens-result.json")" = "disabled" ] \
    && pass "off by default: recorded as disabled" || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "off by default: nothing is filled" || fail "lodash is '$(lic "$D" lodash)'"

D="$(new_run lr-on)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(lic "$D" lodash)" = "MIT -" ] && pass "a component with no licence is filled from the registry" || fail "lodash is '$(lic "$D" lodash)'"
jq -e '[.components[] | select(.name=="lodash")][0].properties | any(.name=="bomlens:licenseSource" and .value=="registry (deps.dev)")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "the filled licence is marked as coming from the registry" || fail "no bomlens:licenseSource on lodash"
[ "$(lic "$D" slf4j-api)" = "MIT GPL-2.0-only" ] && pass "a single GPL the registry contradicts is replaced, the old value kept" || fail "slf4j-api is '$(lic "$D" slf4j-api)'"
[ "$(lic "$D" mysql-connector-java)" = "GPL-2.0-only -" ] && pass "a GPL the registry has no answer for is kept" || fail "mysql-connector-java is '$(lic "$D" mysql-connector-java)'"
[ "$(lic "$D" gplpkg)" = "GPL-3.0-only -" ] && pass "a GPL the registry confirms is kept, with no superseded mark" || fail "gplpkg is '$(lic "$D" gplpkg)'"
[ "$(lic "$D" requests)" = "Apache-2.0 -" ] && pass "a licence not on the verify list is not asked about" || fail "requests is '$(lic "$D" requests)'"
[ "$(jq -c '[.steps[] | select(.id=="license-registry")][0] | [.status, .counts.candidates, .counts.filled, .counts.superseded, .counts.confirmed, .counts.not_found]' "$D/bomlens-result.json")" = '["ok",4,1,1,1,1]' ] \
    && pass "the manifest records the step as ok with its counts" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"

D="$(new_run lr-err)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
mkdir -p "$WORK/lr-bad"; cp "$LRF"/*.json "$WORK/lr-bad/"; echo 'not json' > "$WORK/lr-bad/npm_lodash_4.17.21.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$WORK/lr-bad"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.lookup_failed)"' "$D/bomlens-result.json")" = "degraded unavailable 1" ] \
    && pass "a lookup that failed leaves the step degraded (unavailable)" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "a failed lookup changes nothing for that component" || fail "lodash is '$(lic "$D" lodash)'"

D="$(new_run lr-unreachable)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_API=http://127.0.0.1:9/v3
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.lookup_failed)"' "$D/bomlens-result.json")" = "degraded unavailable 4" ] \
    && pass "an endpoint that does not answer (LICENSE_REGISTRY_API): degraded, unavailable, every lookup counted as failed" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" slf4j-api)" = "GPL-2.0-only -" ] \
    && pass "with no answer the recorded licences are left as they were" || fail "slf4j-api is '$(lic "$D" slf4j-api)'"

echo "== license-registry: evidence, deprecated ids, mixed answers, nesting, supplier SBOMs, budget =="
echo '{"licenses":["MIT"]}' > "$LRF/npm_withtext_1.0.json"
echo '{"licenses":["MIT"]}' > "$LRF/npm_concluded_1.0.json"
echo '{"licenses":["GPL-2.0-or-later"]}' > "$LRF/npm_oldid_1.0.json"
echo '{"licenses":["GPL-2.0-only","MIT"]}' > "$LRF/maven_org.x_dual_1.0.json"
echo '{"licenses":["MIT","non-standard"]}' > "$LRF/npm_nonstd_1.0.json"
echo '{"licenses":["MIT"]}' > "$LRF/npm_freetext_1.0.json"
echo '{"licenses":["Apache-2.0"]}' > "$LRF/npm_inner_1.0.json"
cat > "$WORK/lr-bom2.json" <<'EOF2'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"demo","version":"1.0","bom-ref":"root"}},
 "components":[
  {"type":"library","name":"withtext","version":"1.0","purl":"pkg:npm/withtext@1.0","bom-ref":"a","licenses":[{"license":{"url":"https://example.com/LICENSE","text":{"content":"Proprietary terms"}}}]},
  {"type":"library","name":"concluded","version":"1.0","purl":"pkg:npm/concluded@1.0","bom-ref":"b","licenses":[{"license":{"id":"GPL-3.0-only","acknowledgement":"concluded"}}]},
  {"type":"library","name":"oldid","version":"1.0","purl":"pkg:npm/oldid@1.0","bom-ref":"c","licenses":[{"license":{"id":"GPL-2.0+"}}]},
  {"type":"library","name":"dual","version":"1.0","purl":"pkg:maven/org.x/dual@1.0","bom-ref":"d","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"nonstd","version":"1.0","purl":"pkg:npm/nonstd@1.0","bom-ref":"e","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
  {"type":"library","name":"freetext","version":"1.0","purl":"pkg:npm/freetext@1.0","bom-ref":"f","licenses":[{"license":{"name":"GNU General Public License v2.0"}}]},
  {"type":"library","name":"outer","version":"1.0","purl":"pkg:npm/outer@1.0","bom-ref":"g","licenses":[{"license":{"id":"MIT"}}],
   "components":[{"type":"library","name":"inner","version":"1.0","purl":"pkg:npm/inner@1.0","bom-ref":"h"}]}
 ]}
EOF2
D="$(new_run lr-edge)"; cp "$WORK/lr-bom2.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
jq -e '[.components[] | select(.name=="withtext")][0].licenses[0].license.text.content == "Proprietary terms"' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a licence given only as text and url is kept, not filled over" || fail "withtext is $(jq -c '[.components[] | select(.name=="withtext")][0].licenses' "$D/demo_1.0_bom.json")"
[ "$(lic "$D" concluded)" = "GPL-3.0-only -" ] && pass "a concluded licence is not checked against the registry" || fail "concluded is '$(lic "$D" concluded)'"
[ "$(lic "$D" oldid)" = "GPL-2.0+ -" ] && pass "GPL-2.0+ against GPL-2.0-or-later is a confirmation, not a replacement" || fail "oldid is '$(lic "$D" oldid)'"
[ "$(lic "$D" dual)" = "GPL-2.0-only -" ] && pass "an answer that lists the recorded licence among others confirms it" || fail "dual is '$(lic "$D" dual)'"
[ "$(lic "$D" nonstd)" = "GPL-3.0-only -" ] && pass "an answer with a non-standard licence is not used" || fail "nonstd is '$(lic "$D" nonstd)'"
[ "$(lic "$D" freetext)" = "MIT GPL-2.0-only" ] && pass "a GPL written as free text is normalized first, then checked" || fail "freetext is '$(lic "$D" freetext)'"
jq -e '[.components[] | select(.name=="outer")][0].components[0].licenses[0] | (.expression // .license.id) == "Apache-2.0"' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a nested component is filled" || fail "inner is $(jq -c '[.components[] | select(.name=="outer")][0].components' "$D/demo_1.0_bom.json")"
jq -e '[.components[] | select(.name=="freetext")][0].properties | any(.name=="bomlens:licenseClass" and .value=="permissive")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a replaced licence is classified again (normalize runs after a change)" || fail "freetext props $(jq -c '[.components[] | select(.name=="freetext")][0].properties' "$D/demo_1.0_bom.json")"
run_again="$(new_run lr-again)"; cp "$D/demo_1.0_bom.json" "$run_again/demo_1.0_bom.json"
run_engine "$run_again" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.counts.filled) \(.counts.superseded)"' "$run_again/bomlens-result.json")" = "0 0" ] \
    && pass "a second run over its own output changes nothing" || fail "second run: $(jq -c '[.steps[] | select(.id=="license-registry")][0].counts' "$run_again/bomlens-result.json")"

D="$(new_run lr-analyze)"
run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$WORK/lr-bom.json" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(lic "$D" slf4j-api)" = "GPL-2.0-only -" ] && [ "$(lic "$D" lodash)" = "MIT -" ] \
    && pass "a supplier's SBOM (ANALYZE): a missing licence is filled, a declared one is never replaced" \
    || fail "slf4j-api '$(lic "$D" slf4j-api)', lodash '$(lic "$D" lodash)'"

D="$(new_run lr-budget)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
_t0=$(date +%s)
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF" LICENSE_REGISTRY_FIXTURE_DELAY=6 LICENSE_REGISTRY_BUDGET=1
_t1=$(date +%s)
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.budget_reached)"' "$D/bomlens-result.json")" = "degraded budget_exhausted 4" ] \
    && pass "answers slower than the budget: degraded, budget_exhausted, all four counted" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "what did not answer in time is left as it was" || fail "lodash is '$(lic "$D" lodash)'"
echo "  (license-registry with a 1 s budget and 6 s answers took $((_t1 - _t0)) s for the whole run)"

echo "== a source that declares dependencies but yields no component =="
DECL="$WORK/declares"; mkdir -p "$DECL"
printf '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "2.31.0"\n' > "$DECL/pyproject.toml"
NODECL="$WORK/declares-nothing"; mkdir -p "$NODECL"
printf '[tool.poetry.dependencies]\npython = "^3.11"\n' > "$NODECL/pyproject.toml"
empty_bom() { echo '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"x","version":"1"}},"components":[]}' > "$1/demo_1.0_bom.json"; }
gen_of() { jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }
D="$(new_run empty-declared empty)"; empty_bom "$D"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DECL"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "degraded no_components succeeded_degraded" ] \
    && pass "generate is degraded (no_components) and the run succeeded_degraded" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json")"
jq -r '.metadata.properties[]? | select(.name=="bomlens:sbom-empty-with-manifests") | .value' "$D/demo_1.0_bom.json" | grep -qx 'pyproject.toml' \
    && pass "the SBOM names the manifest in bomlens:sbom-empty-with-manifests" \
    || fail "SBOM properties: $(jq -c '.metadata.properties' "$D/demo_1.0_bom.json")"
err="$(schema_errors "$D/bomlens-result.json")"
[ -z "$err" ] && pass "the no_components manifest validates against the schema" || fail "schema errors" "$err"
# A later step that fills the SBOM (here the conda sidecar build-prep leaves
# for the merge) means the scan did find the dependencies: no flag.
D="$(new_run empty-then-filled empty)"; empty_bom "$D"
printf 'dependencies:\n  - numpy=1.26.4\n' > "$DECL/environment.yml"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"numpy","version":"1.26.4","purl":"pkg:conda/numpy@1.26.4","properties":[{"name":"bomlens:layer","value":"conda"}]}]}' > "$D/demo_1.0_conda.cdx.json"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DECL"
rm -f "$DECL/environment.yml"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "ok null succeeded" ] \
    && ! jq -e 'any(.metadata.properties[]?; .name=="bomlens:sbom-empty-with-manifests")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a component added by a later step (conda merge) leaves no empty-manifest flag" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json"), components $(jq '.components | length' "$D/demo_1.0_bom.json")"
D="$(new_run empty-undeclared empty)"; empty_bom "$D"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$NODECL"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "ok null succeeded" ] \
    && pass "a manifest with nothing declared and no component is a plain success" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json")"
# Against a copy whose manifest finder finds nothing, the declared case must
# read succeeded: that is the "no detection, still a pass" the check catches.
MUT3="$WORK/lib-mutant-manifests"
cp -R "$ROOT_DIR/docker/lib" "$MUT3"
printf '\nsource_manifests() { printf ""; }\n' >> "$MUT3/source-detect.sh"
D="$(new_run empty-declared-mutant empty)"; empty_bom "$D"; run_engine "$D" "$MUT3" SOURCE_ROOT="$DECL"
[ "$(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)" = "succeeded" ] \
    && pass "without the manifest check the same run reads succeeded, so the check above can fail" \
    || fail "the mutant run is $(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)"

echo "== MODE=PLAN: the execution plan of a source scan =="
PLAN_SCHEMA="$ROOT_DIR/schemas/engine-plan-1.json"
plan_schema_errors() {
    if [ -z "$JSPY" ]; then
        # Locally a missing jsonschema skips the check; in CI it must run.
        [ -n "${CI:-}" ] && echo "jsonschema is not installed, so the plan was not validated"
        return 0
    fi
    "$JSPY" - "$PLAN_SCHEMA" "$1" <<'PY'
import json, sys
import jsonschema
v = jsonschema.Draft202012Validator(json.load(open(sys.argv[1])))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in v.iter_errors(json.load(open(sys.argv[2])))))
PY
}
plan_run() {  # plan_run <case> <source-dir> [VAR=value ...]
    local d="$WORK/plan-$1" src="$2"; shift 2; mkdir -p "$d"
    ( cd "$d" && env MODE=PLAN PROJECT_NAME=demo PROJECT_VERSION=1.0 SOURCE_ROOT="$src" HOST_OUTPUT_DIR="$d" \
        BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_IMAGE_REF=ghcr.io/example/bomlens:1 \
        BOMLENS_IMAGE_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
        "$@" bash "$ENTRY" ) > "$d.log" 2>&1
    echo $? > "$d.rc"
    printf '%s' "$d"
}
PSRC="$WORK/plan-src-node"; mkdir -p "$PSRC"; echo '{"name":"x","dependencies":{"lodash":"^4"}}' > "$PSRC/package.json"
P="$(plan_run node "$PSRC")"
[ -f "$P/bomlens-plan.json" ] && pass "MODE=PLAN writes bomlens-plan.json" || fail "no plan" "$(tail -5 "$P.log")"
err="$(plan_schema_errors "$P/bomlens-plan.json")"
[ -z "$err" ] && pass "the plan validates against schemas/engine-plan-1.json" || fail "plan schema errors" "$err"
[ "$(jq -r '.status + " " + .input.detected_ecosystem + " " + .stages[0].image' "$P/bomlens-plan.json")" = "ok node ghcr.io/cdxgen/cdxgen-alpine-node24:13.2.0" ] \
    && pass "a Node.js source plans the cdxgen Node.js image" || fail "plan: $(jq -c '[.status, .input, .stages[0].image]' "$P/bomlens-plan.json")"
[ "$(jq -r '.stages[0].image_digest' "$P/bomlens-plan.json")" = "$(jq -r '.digests["ghcr.io/cdxgen/cdxgen-alpine-node24"]' "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
    && pass "stage 1 is pinned by digest" || fail "stage 1 digest is $(jq -r '.stages[0].image_digest' "$P/bomlens-plan.json")"
[ "$(jq -r '.stages[0].args | join(" ")' "$P/bomlens-plan.json")" = "/tmp/build-prep.sh /app /out/demo_1.0_bom.json 1.6" ] \
    && pass "stage 1 runs build-prep.sh with the CLI's arguments" || fail "stage 1 args: $(jq -c '.stages[0].args' "$P/bomlens-plan.json")"
cmp -s "$P/bomlens-plan/build-prep.sh" "$ROOT_DIR/docker/lib/build-prep.sh" && [ -f "$P/bomlens-plan/identify-conda.py" ] \
    && pass "the files stage 1 mounts are copied next to the plan" || fail "bomlens-plan/ holds: $(ls "$P/bomlens-plan" 2>&1)"
[ "$(jq -r '.stages[1] | .image + " " + .env.MODE + " " + .env.BOMLENS_RUN_INPUT' "$P/bomlens-plan.json")" = "ghcr.io/example/bomlens:1 POSTPROCESS demo_1.0_bom.json" ] \
    && pass "stage 2 is this image in POSTPROCESS mode on stage 1's SBOM" || fail "stage 2: $(jq -c '.stages[1] | [.image, .env]' "$P/bomlens-plan.json")"
[ "$(jq -r '[.stages[0].mounts[] | select(.role=="source") | .mode] | first' "$P/bomlens-plan.json") $(jq -r '[.stages[1].mounts[] | select(.role=="source") | .mode] | first' "$P/bomlens-plan.json")" = "rw ro" ] \
    && pass "the source is writable in stage 1 only" || fail "source mounts: $(jq -c '[.stages[].mounts[] | select(.role=="source")]' "$P/bomlens-plan.json")"
PSRC2="$WORK/plan-src-android"; mkdir -p "$PSRC2/app"
printf 'plugins { id "com.android.application" }\nandroid { compileSdk 34 }\n' > "$PSRC2/app/build.gradle"; : > "$PSRC2/settings.gradle"
printf 'plugins { id "com.android.application" }\n' > "$PSRC2/build.gradle"
P="$(plan_run android "$PSRC2")"
[ "$(jq -r '.status + " " + .reason + " " + (.stages | length | tostring)' "$P/bomlens-plan.json")" = "unsupported android-sdk-image 0" ] \
    && pass "an Android source is unsupported (the SDK image is not published), with no stages" \
    || fail "android plan: $(jq -c '[.status, .reason, .detail]' "$P/bomlens-plan.json")"
[ "$(cat "$P.rc") $(jq -r '[.steps[] | select(.id=="plan")][0] | "\(.status) \(.reason)"' "$P/bomlens-result.json") $(jq -r .run.status "$P/bomlens-result.json")" = "0 skipped not_installed succeeded_degraded" ] \
    && pass "an unsupported plan exits 0 and the manifest says plan skipped (not_installed), run succeeded_degraded" \
    || fail "rc $(cat "$P.rc"), manifest $(jq -c '[.run.status, .steps]' "$P/bomlens-result.json")"

P="$(plan_run node-opts "$PSRC" BYTE_STABLE=true GOTOOLCHAIN=local HOST_UID=501 HOST_GID=20)"
[ "$(jq -r '.stages[0].env | "\(.FETCH_LICENSE) \(.HOST_GOTOOLCHAIN)"' "$P/bomlens-plan.json")" = "false local" ] \
    && pass "BYTE_STABLE turns stage 1's license lookup off; GOTOOLCHAIN reaches it as HOST_GOTOOLCHAIN" \
    || fail "stage 1 env: $(jq -c '.stages[0].env' "$P/bomlens-plan.json")"
P="$(plan_run node-badtc "$PSRC" GOTOOLCHAIN='local;rm -rf /')"
[ "$(jq -r '.stages[0].env.HOST_GOTOOLCHAIN // "absent"' "$P/bomlens-plan.json")" = "absent" ] \
    && pass "a GOTOOLCHAIN that is not a toolchain name is not passed on" || fail "HOST_GOTOOLCHAIN: $(jq -r '.stages[0].env.HOST_GOTOOLCHAIN' "$P/bomlens-plan.json")"
[ "$(jq -r '[.stages[0].mounts[] | select(.role=="guard-state") | .target] | first' "$P/bomlens-plan.json") $(jq -r '.stages[0].env_from_caller | has("BOMLENS_GUARD_ID")' "$P/bomlens-plan.json")" = "/bomlens-state true" ] \
    && pass "stage 1 offers the guard-state mount and BOMLENS_GUARD_ID, so a killed stage 1 can be undone" \
    || fail "guard state: $(jq -c '[.stages[0].mounts, .stages[0].env_from_caller]' "$P/bomlens-plan.json")"
jq -e '(.stages[0].env_passthrough | index("HOST_UID")) and (.stages[1].env_passthrough | index("HOST_UID")) and (.stages[1].env_passthrough | index("BOMLENS_INCLUDE_NON_SHIPPED"))' "$P/bomlens-plan.json" >/dev/null \
    && pass "HOST_UID/HOST_GID pass to both stages, BOMLENS_INCLUDE_NON_SHIPPED to stage 2 (its fallback reads it)" \
    || fail "passthrough: $(jq -c '[.stages[].env_passthrough]' "$P/bomlens-plan.json")"
[ "$(jq -r '[.outputs[] | select(.role=="plan") | .path] | first' "$P/bomlens-result.json")" = "bomlens-plan.json" ] \
    && pass "the result manifest lists bomlens-plan.json as the plan output" || fail "outputs: $(jq -c '.outputs' "$P/bomlens-result.json")"

# A re-plan in the same folder removes the earlier run's stage 1 outputs.
P="$WORK/plan-stale"; mkdir -p "$P"
echo stale > "$P/demo_1.0_bom.json"; echo stale > "$P/demo_1.0_conda.cdx.json"; echo stale > "$P/bomlens-plan.json"
P="$(plan_run stale "$PSRC")"
[ ! -e "$P/demo_1.0_bom.json" ] && [ ! -e "$P/demo_1.0_conda.cdx.json" ] && [ "$(jq -r .status "$P/bomlens-plan.json" 2>/dev/null)" = "ok" ] \
    && pass "PLAN removes an earlier run's SBOM and conda sidecar, and replaces the plan" \
    || fail "left: $(ls "$P")"

EMPTYSRC="$WORK/plan-src-empty"; mkdir -p "$EMPTYSRC"
P="$(plan_run empty "$EMPTYSRC")"
[ "$(cat "$P.rc") $(jq -r '.run.status + " " + ([.steps[] | select(.id=="plan")][0].status)' "$P/bomlens-result.json")" != "0 succeeded ok" ] \
    && [ ! -f "$P/bomlens-plan.json" ] && [ "$(jq -r '[.steps[] | select(.id=="plan")][0].status' "$P/bomlens-result.json")" = "failed" ] \
    && pass "an empty source is refused: no plan, plan step failed" \
    || fail "empty source: rc $(cat "$P.rc"), $(jq -c '[.run.status, .steps]' "$P/bomlens-result.json")"
missing=""
for lang in rust go ruby java python node php dotnet swift unknown; do
    img="$(bash -c ". '$ROOT_DIR/docker/lib/source-detect.sh' >/dev/null 2>&1; img_for_lang $lang")"
    jq -e --arg i "${img%:*}" --arg t "${img##*:}" '.tag == $t and (.digests[$i] // "" | startswith("sha256:"))' \
        "$ROOT_DIR/docker/lib/cdxgen-images.json" >/dev/null || missing="$missing $img"
done
[ -z "$missing" ] && pass "cdxgen-images.json pins every image img_for_lang returns, at CDXGEN_TAG" \
    || fail "no pinned digest for:$missing (run scripts/update-cdxgen-digests.sh)"

echo "== POSTPROCESS takes over the manifest-only fallback when told stage 1 failed =="
if ! command -v syft >/dev/null 2>&1 && [ -n "${CI:-}" ]; then
    fail "syft is not installed on this CI runner, so the stage 2 fallback is not tested"
elif command -v syft >/dev/null 2>&1; then
    FB="$WORK/fb-src"; mkdir -p "$FB"; printf 'requests==2.31.0\n' > "$FB/requirements.txt"
    D="$(new_run fallback empty)"
    printf 'npm ERR! getaddrinfo ENOTFOUND registry.npmjs.org\n' > "$D/bomlens-stage1.log"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_LOG=bomlens-stage1.log
    [ "$(jq -r '[.components[] | select(.type=="library") | .name] | join(",")' "$D/demo_1.0_bom.json" 2>/dev/null)" = "requests" ] \
        && pass "a failed stage 1 is replaced by the syft scan of the source" \
        || fail "fallback SBOM: $(jq -c '[.components[]?.name]' "$D/demo_1.0_bom.json" 2>&1)" "$(tail -8 "$D.log")"
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "network" ] \
        && pass "the reason is read from the stage 1 log (network)" \
        || fail "sbom-tool-degraded is $(jq -c '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded")]' "$D/demo_1.0_bom.json" 2>&1)"
    [ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason) \(.stage)"' "$D/bomlens-result.json")" = "degraded fallback 1" ] \
        && pass "generate is recorded as degraded (fallback)" \
        || fail "generate is $(jq -c '[.steps[] | select(.id=="generate")]' "$D/bomlens-result.json")"
    D="$(new_run fallback-oom empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=137 BOMLENS_STAGE1_OOM=true
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "oom" ] \
        && pass "a stage 1 killed for memory is recorded as oom" || fail "oom case: $(tail -5 "$D.log")"
    D="$(new_run fallback-traversal empty)"
    printf 'getaddrinfo ENOTFOUND\n' > "$WORK/outside.log"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_LOG=../outside.log
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "cdxgen-crash" ] \
        && pass "a stage 1 log path outside the output folder is not read" || fail "traversal case: $(jq -c '[.metadata.properties[]?]' "$D/demo_1.0_bom.json" 2>&1)"
    D="$(new_run fallback-fails empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$WORK/no-such-source" BOMLENS_STAGE1_EXIT=1
    rc=$?
    [ "$rc" = 1 ] && [ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "failed" ] \
        && pass "when the fallback fails too, the run exits 1 with generate failed" \
        || fail "rc $rc, generate $(jq -c '[.steps[] | select(.id=="generate")]' "$D/bomlens-result.json")"
    D="$(new_run stage1-ok)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=0
    [ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "ok" ] \
        && [ "$(jq -r '[.components[] | .name] | sort | join(",")' "$D/demo_1.0_bom.json")" != "requests" ] \
        && pass "a stage 1 that succeeded is post-processed as it is (no fallback)" || fail "stage1-ok: $(tail -5 "$D.log")"
else
    echo "  SKIP: syft is not installed on this host"
fi

echo "== every step label in entrypoint.sh is documented =="
missing=""
for id in $(grep -v '^[[:space:]]*#' "$ENTRY" | grep -oE '(run_optional_step|er_record|er_phase) [a-z][a-z0-9-]+' | awk '{print $2}' | sort -u); do
    printf '%s\n' "$DOC_STEPS" | grep -qx "$id" || missing="$missing $id"
done
[ -z "$missing" ] && pass "all step ids used in entrypoint.sh are in the contract's step table" \
    || fail "step ids missing from docs/reference/engine-contract.md:$missing"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
