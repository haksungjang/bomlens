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

D="$(new_run dl-noinput)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$WORK/no-such-tree" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub"
[ "$(dl_step "$D")" = "skipped no_input" ] && pass "no source tree: skipped, no_input" || fail "deep-license is $(dl_step "$D")"

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
