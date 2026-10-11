#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# engine-result.sh - the run's result manifest (bomlens-result.json).
#
# A program that runs this image as its scan engine needs to know, without
# reading the human log, which steps ran, which were turned off or could not
# run, which failed, and where each output is. entrypoint.sh records every step
# here as it goes (er_record, also called by run_optional_step) and writes the
# manifest from an EXIT trap, so a run that stops early still leaves one. The
# format is the engine contract in docs/reference/engine-contract.md, checked
# against schemas/engine-result-1.json by tests/test-engine-contract.sh.
#
# Recording rule: a step that applies to this mode is always recorded, as ok,
# degraded, failed, skipped (it could not run: no input, tool not installed) or
# disabled (a setting turned it off). A step that does not apply to the mode at
# all (CPE enrichment of an AI model) is not recorded.

ENGINE_CONTRACT_VERSION="1.0.0"
ENGINE_RESULT_NAME="bomlens-result.json"

er_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Start the run record. Safe to call once; later calls keep the first.
er_init() {
    [ -n "${ER_STEPS:-}" ] && return 0
    ER_STEPS="$(mktemp "${TMPDIR:-/tmp}/bomlens-steps.XXXXXX" 2>/dev/null)" || ER_STEPS=""
    ER_STARTED="$(er_now)"
    # A manifest left from an earlier run in the same folder must not be read as
    # this run's: remove it now, so a run killed before its trap leaves none.
    [ -n "${HOST_OUTPUT_DIR:-}" ] && rm -f "$HOST_OUTPUT_DIR/$ENGINE_RESULT_NAME" 2>/dev/null
    return 0
}

# Mark the step now running outside run_optional_step, so an exit inside it is
# recorded as its failure. er_phase_end clears it once the step has finished.
er_phase() { ER_PHASE="$1"; ER_PHASE_STARTED="$(er_now)"; }
er_phase_end() { ER_PHASE=""; ER_PHASE_STARTED=""; }

# er_record <id> <status> [reason] [detail] [started] [ended] [counts-json]
er_record() {
    [ -n "${ER_STEPS:-}" ] && [ -f "$ER_STEPS" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    local now; now="$(er_now)"
    jq -nc --arg id "$1" --arg st "$2" --arg re "${3:-}" --arg de "${4:-}" \
        --arg s "${5:-$now}" --arg e "${6:-$now}" --arg c "${7:-}" \
        '{id:$id, status:$st,
          reason:(if $re == "" then null else $re end),
          detail:(if $de == "" then null else ($de | gsub("[\u0000-\u001f]"; " ") | .[0:500]) end),
          started_at:$s, ended_at:$e}
         + (if $c == "" then {} else {counts:($c | fromjson? // {})} end)' \
        >> "$ER_STEPS" 2>/dev/null || true
}

# The output role a file plays, from its suffix. Unknown suffixes are "other".
_er_role() {
    case "$1" in
        *_bom.json) echo "sbom.cyclonedx" ;;
        *_bom.spdx.json) echo "sbom.spdx" ;;
        *_bom.spdx3.json) echo "sbom.spdx3" ;;
        *_security_trivy.json) echo "vulnerabilities.trivy" ;;
        *_security.json) echo "vulnerabilities.all" ;;
        *_security_grype.json|*_security_cvebintool.json|*_security_yocto.json) echo "vulnerabilities.other" ;;
        *_scancode.json) echo "license-scan.scancode" ;;
        *_vendored.cdx.json) echo "vendored.cyclonedx" ;;
        *_conformance.json) echo "conformance" ;;
        *_input.json) echo "input-description" ;;
        *) echo "other" ;;
    esac
}

_er_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

_er_input_kind() {
    case "$1" in
        SOURCE|POSTPROCESS) echo source ;;
        IMAGE) echo image ;;
        ANALYZE|MERGE) echo sbom ;;
        BINARY) echo binary ;;
        ROOTFS) echo rootfs ;;
        FIRMWARE) echo firmware ;;
        AIBOM|MODELFILE|AIDECLARE) echo ai-model ;;
        DATASET) echo dataset ;;
        *) echo unknown ;;
    esac
}

# The EXIT trap: write the manifest, then exit again with the run's own code,
# so nothing er_finish does can change it.
er_exit_trap() {
    local rc=$?
    set +e
    er_finish "$rc"
    exit "$rc"
}

# Write the manifest. Called from the EXIT trap with the script's exit code.
# Never fails and never changes the exit code.
er_finish() {
    # Errexit off for this function only: a failing jq here must not end the
    # script with its own status instead of the run's.
    local -
    set +e
    local rc="${1:-0}"
    [ -n "${ER_STEPS:-}" ] && [ -f "$ER_STEPS" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    local outdir="${HOST_OUTPUT_DIR:-}"
    [ -n "$outdir" ] && [ -d "$outdir" ] || outdir="."
    local bom="${OUTPUT_FILE:-}" sec="${OUT_PREFIX:-}_security.json"
    [ -f "$outdir/$(basename "$bom")" ] && bom="$outdir/$(basename "$bom")"
    [ -f "$outdir/$(basename "$sec")" ] && sec="$outdir/$(basename "$sec")"

    # Outcomes only visible after the fact, read from what the steps left behind.
    local props=""
    [ -n "$bom" ] && [ -f "$bom" ] && props="$(jq -c '[.metadata.properties[]? | .name]' "$bom" 2>/dev/null)"
    [ -n "$props" ] || props="[]"
    # A security report counts only when scan-security ran in this run: a file
    # left in the folder by an earlier run says nothing about this one.
    local scan_error="" sec_present=false sec_ran=false
    grep -q '"id":"scan-security","status":"ok"' "$ER_STEPS" 2>/dev/null && sec_ran=true
    if [ "$sec_ran" = true ] && [ -f "$sec" ]; then
        sec_present=true
        scan_error="$(jq -r '.ScanError.Message // empty' "$sec" 2>/dev/null)"
    fi

    # Output files: every artifact this run listed, found in the output folder.
    # When the caller asked for the stale-artifact cleanup, every file under
    # this run's prefix with a known suffix is also this run's own, including
    # reports a mode writes without listing them (conformance for a scan).
    local outputs="[]" f base path
    local -a seen=() extra=()
    if [ -n "${BOMLENS_RUN_INPUT:-}" ] || [ "${BOMLENS_ARTIFACT_CLEANUP:-}" = "1" ]; then
        for f in "${KNOWN_ARTIFACT_SUFFIXES[@]:-}"; do
            [ -n "$f" ] && extra+=("${OUT_PREFIX:-}$f")
        done
    fi
    [ "$sec_ran" = true ] && extra+=("${OUT_PREFIX:-}_security_trivy.json")
    for f in "${ARTIFACTS[@]:-}" "${extra[@]:-}"; do
        [ -n "$f" ] || continue
        base="$(basename "$f")"
        case " ${seen[*]:-} " in *" $base "*) continue ;; esac
        path=""
        if [ -f "$outdir/$base" ]; then path="$outdir/$base"; elif [ -f "$f" ]; then path="$f"; fi
        [ -n "$path" ] || continue
        seen+=("$base")
        outputs="$(jq -c --arg role "$(_er_role "$base")" --arg p "$base" \
            --arg h "$(_er_sha256 "$path")" --argjson b "$(wc -c < "$path" | tr -d '[:space:]')" \
            '. + [{role:$role, path:$p, sha256:$h, bytes:$b}]' <<<"$outputs")"
    done
    # With no other engine merged in, the full report is Trivy's own output.
    if ! jq -e 'any(.[]; .role == "vulnerabilities.trivy")' <<<"$outputs" >/dev/null; then
        outputs="$(jq -c '. + [.[] | select(.role == "vulnerabilities.all") | .role = "vulnerabilities.trivy"]' <<<"$outputs")"
    fi

    # Vulnerability engines that actually produced results for this run.
    local engines="[]" e
    if [ "$sec_present" = true ]; then
        engines='["trivy"]'
        for e in grype cvebintool yocto; do
            if [ -f "$outdir/${OUT_PREFIX}_security_${e}.json" ] || [ -f "${OUT_PREFIX}_security_${e}.json" ]; then
                [ "$e" = cvebintool ] && e="cve-bin-tool"
                engines="$(jq -c --arg e "$e" '. + [$e]' <<<"$engines")"
            fi
        done
    fi

    # Tool versions: the generator recorded in the SBOM, then the bundled tools.
    local tools="{}"
    [ -n "$bom" ] && [ -f "$bom" ] && tools="$(jq -c '[(.metadata.tools // [] | if type == "object" then .components[]? else .[]? end)
        | objects | select(.name and .version and .name != "BomLens") | {key:.name, value:(.version|tostring)}] | from_entries' "$bom" 2>/dev/null)"
    [ -n "$tools" ] || tools="{}"
    [ -n "${BOMLENS_SYFT_VERSION:-}" ] && tools="$(jq -c --arg v "${BOMLENS_SYFT_VERSION#v}" '. + {syft:$v}' <<<"$tools")"
    local trivy_db="null"
    if [ "$sec_present" = true ] && command -v trivy >/dev/null 2>&1; then
        local tv; tv="$(trivy version --format json 2>/dev/null)"
        if [ -n "$tv" ]; then
            tools="$(jq -c --argjson t "$tv" '. + (if $t.Version then {trivy:$t.Version} else {} end)' <<<"$tools" 2>/dev/null || echo "$tools")"
            trivy_db="$(jq -c '.VulnerabilityDB // null | if . then {schema_version:.Version, updated_at:.UpdatedAt, downloaded_at:.DownloadedAt} else null end' <<<"$tv" 2>/dev/null || echo null)"
        fi
    fi

    # A non-zero exit inside a step that is not wrapped by run_optional_step
    # (generation, the fail-closed metadata stamp) is that step's failure.
    if [ "$rc" != "0" ] && [ -n "${ER_PHASE:-}" ]; then
        er_record "$ER_PHASE" failed failed "exit code $rc" "${ER_PHASE_STARTED:-}"
    fi

    local ended; ended="$(er_now)"
    local target=""
    [ "${SCAN_MODE:-}" = "IMAGE" ] && target="${TARGET_IMAGE:-}"
    local tmp="$outdir/.${ENGINE_RESULT_NAME}.tmp.$$"
    jq -s \
        --arg cv "$ENGINE_CONTRACT_VERSION" --arg ev "${BOMLENS_VERSION:-}" \
        --arg img "${BOMLENS_IMAGE_REF:-}" --arg dig "${BOMLENS_IMAGE_DIGEST:-}" \
        --arg kind "$(_er_input_kind "${SCAN_MODE:-}")" --arg mode "${SCAN_MODE:-}" \
        --arg target "$target" --arg started "${ER_STARTED:-$ended}" --arg ended "$ended" \
        --argjson rc "$rc" --argjson props "$props" --arg scanerr "$scan_error" \
        --argjson secpresent "$sec_present" --argjson outputs "$outputs" \
        --argjson engines "$engines" --argjson tools "$tools" --argjson tdb "$trivy_db" '
        def rank: {"failed":4, "degraded":3, "skipped":2, "disabled":1, "ok":0}[.] // 0;
        # One entry per step id, in first-seen order: the worst status wins, the
        # time span covers every call (conformance can run twice in one scan).
        (reduce .[] as $s ({order: [], by: {}};
            if .by[$s.id] then
                .by[$s.id] |= (if ($s.status | rank) > (.status | rank)
                               then . + {status:$s.status, reason:$s.reason, detail:$s.detail} else . end
                               | .ended_at = $s.ended_at
                               | .counts = ((.counts // {}) + ($s.counts // {}))
                               | if .counts == {} then del(.counts) else . end)
            else .order += [$s.id] | .by[$s.id] = $s end)) as $acc
        | [ $acc.order[] as $id | $acc.by[$id] ] as $steps
        # Facts only visible afterwards: a Trivy run that wrote ScanError failed
        # even though its script returned 0, and a check whose data was missing
        # stamped the SBOM instead of failing.
        | ($steps | map(
            if .id == "scan-security" and .status == "ok" and $scanerr != "" then
                .status = "failed" | .reason = "failed" | .detail = ($scanerr | .[0:500])
            elif .id == "scan-security" and .status == "ok" and ($secpresent | not) then
                .status = "skipped" | .reason = "not_installed"
            elif .id == "enrich-eol" and .status == "ok" and ($props | index("bomlens:eol-check-unavailable")) then
                .status = "degraded" | .reason = "unavailable"
            elif .id == "enrich-malicious" and .status == "ok" and ($props | index("bomlens:malicious-check-unavailable")) then
                .status = "degraded" | .reason = "unavailable"
            else . end
            # The SBOM a POSTPROCESS run reads was generated by the stage-1
            # language image before this container started.
            | .stage = (if .id == "generate" and $mode == "POSTPROCESS" then 1 else 2 end))) as $steps
        | (if $rc == 130 or $rc == 143 then "cancelled"
           elif $rc != 0 then "failed"
           # A step that was asked for and could not run (its tool missing, its
           # input over a limit, its image unavailable) leaves the result short
           # of what was asked, the same as a failed one. Only "nothing to read"
           # (no_input) is neutral.
           elif any($steps[]; .status == "failed" or .status == "degraded"
                    or (.status == "skipped" and .reason != "no_input")) then "succeeded_degraded"
           else "succeeded" end) as $status
        | {
            contract: {name: "bomlens-engine", version: $cv},
            engine: {
              version: (if $ev == "" then null else $ev end),
              image: (if $img == "" then null else $img end),
              image_digest: (if $dig == "" then null else $dig end)
            },
            input: {
              kind: $kind, mode: $mode,
              target: (if $target == "" then null else $target end)
            },
            run: {
              status: $status,
              reason: (if $status == "cancelled" then "cancelled"
                       elif $status == "failed" then "exit_code"
                       elif $status == "succeeded_degraded" then "step_failed_or_degraded"
                       else null end),
              started_at: $started, ended_at: $ended, exit_code: $rc
            },
            steps: $steps,
            tools: $tools,
            engines: $engines,
            data_sources: {trivy_db: $tdb},
            outputs: $outputs
          }' "$ER_STEPS" > "$tmp" 2>/dev/null \
        && mv "$tmp" "$outdir/$ENGINE_RESULT_NAME" \
        || rm -f "$tmp"
    if [[ "${HOST_UID:-}" =~ ^[0-9]+$ ]] && [[ "${HOST_GID:-}" =~ ^[0-9]+$ ]]; then
        chown "${HOST_UID}:${HOST_GID}" "$outdir/$ENGINE_RESULT_NAME" 2>/dev/null || true
    fi
    rm -f "$ER_STEPS"
    return 0
}
