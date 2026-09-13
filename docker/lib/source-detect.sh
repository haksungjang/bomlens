#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# source-detect.sh — shared language detection + cdxgen image selection.
#
# Sourced by BOTH scripts/scan-sbom.sh (host CLI) and docker/entrypoint.sh
# (web UI source scan inside the scanner image). Keeping the logic here means
# the CLI and the UI pick the same cdxgen language image, so a source scan
# resolves transitive dependencies identically on both paths.
#
# Defaults use ${VAR:-default} so a caller that already exported these (the CLI)
# keeps its values; a caller that did not (the UI) gets the defaults.

# renovate: datasource=docker depName=ghcr.io/cyclonedx/cdxgen
CDXGEN_TAG="${CDXGEN_TAG:-v12}"                                  # cdxgen language image tag
# renovate: datasource=docker depName=ghcr.io/cyclonedx/cdxgen
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cyclonedx/cdxgen:v12.5.0}"
# A local name, not a registry one: the Android SDK is not open source and its
# terms bar redistributing it, so this image is built on the machine that uses
# it rather than published. scan-sbom.sh prints the build command when it is
# missing. Point this at a registry to use an image built elsewhere, including
# the ones published before this changed (ghcr.io/sktelecom/bomlens-android-sdk).
ANDROID_IMAGE_PREFIX="${ANDROID_IMAGE_PREFIX:-bomlens-android-sdk}"
ANDROID_API_DEFAULT="${ANDROID_API_DEFAULT:-34}"
# cdxgen does not resolve dependency licenses by default, leaving the SBOM (and
# the NOTICE derived from it) without license data. FETCH_LICENSE=true makes
# cdxgen look up each component's license. On by default; set FETCH_LICENSE=false
# to skip the extra network lookups for a faster, license-sparse scan.
FETCH_LICENSE="${FETCH_LICENSE:-true}"

# Source-scan options that build-prep.sh reads. build-prep runs inside the cdxgen
# container, so every path that starts it (scan-sbom.sh stage 1, the web UI
# container, generate_sbom_cdxgen in entrypoint.sh) passes these on by name.
# docker skips a name-only -e whose variable is unset.
BUILD_PREP_ENV_NAMES="BOMLENS_KEEP_BUILD_OUTPUT BOMLENS_MAVEN_FULL_GRAPH BOMLENS_ANDROID_FULL_GRAPH BOMLENS_NODE_FULL_GRAPH BOMLENS_INCLUDE_NON_SHIPPED"

# Prints "-e NAME" for each name above. Names only, never values, so the output
# is safe to splice into the eval'd docker command in scan-sbom.sh.
build_prep_env_args() {
    local n out=""
    for n in $BUILD_PREP_ENV_NAMES; do out="$out -e $n"; done
    printf '%s' "${out# }"
}

# Folders whose manifests a source scan leaves out by default: test suites and
# their fixtures, examples, benchmarks and demo playgrounds. The GitHub Actions
# workflows under .github/workflows are left out too. None of it ships with the
# product. build-prep.sh runs alone in the cdxgen container and keeps its own
# copy of both lists; tests/test-postprocess.sh checks the copies stay equal.
# BOMLENS_INCLUDE_NON_SHIPPED=1 (or true) keeps everything.
NON_SHIPPED_DIRS="test tests spec fixtures testdata __tests__ e2e example examples benches benchmarks playground samples"
NON_SHIPPED_MANIFEST_RE='(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|setup\.py|setup\.cfg|environment\.ya?ml|pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.lockfile|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|[^/]+\.gemspec|composer\.json|composer\.lock|[^/]+\.(cs|fs|vb)proj|packages\.config|packages\.lock\.json|Directory\.Packages\.props|Package\.swift|Package\.resolved|Podfile|Podfile\.lock|conanfile\.txt|conanfile\.py|vcpkg\.json|METADATA|PKG-INFO)$'

# True unless BOMLENS_INCLUDE_NON_SHIPPED asks to keep the non-shipped trees.
non_shipped_enabled() {
    case "${BOMLENS_INCLUDE_NON_SHIPPED:-}" in 1|true) return 1 ;; esac
    return 0
}

# The glob patterns applied, relative to the scan root, joined with ", ".
non_shipped_globs() {
    local d out=""
    for d in $NON_SHIPPED_DIRS; do out="$out, **/$d/**"; done
    printf '%s' "${out#, }, **/.github/workflows/**"
}

# Prints $1 with every letter as a two-case character class ([tT]), so a glob
# matches the name in any letter case the way cdxgen's ignore list does.
non_shipped_any_case() {
    local s="$1" out="" c i
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        if [[ "$c" == [[:lower:]] ]]; then out="${out}[$c$(printf '%s' "$c" | tr '[:lower:]' '[:upper:]')]"; else out="$out$c"; fi
    done
    printf '%s' "$out"
}

# syft --exclude flags for the same patterns; empty when the option keeps them.
# syft's globs are case-sensitive, so the folder names go in as character
# classes. Read the output with `read -ra`, which does not expand the globs.
non_shipped_syft_args() {
    non_shipped_enabled || return 0
    local d out=""
    for d in $NON_SHIPPED_DIRS; do out="$out --exclude ./**/$(non_shipped_any_case "$d")/**"; done
    printf '%s' "${out# } --exclude ./**/.github/workflows/**"
}

# Manifest files under the non-shipped folders, and workflow files, relative to
# the scan root and sorted. Names match in any letter case, as in cdxgen.
non_shipped_manifests() {
    local root="$1" d re=""
    for d in $NON_SHIPPED_DIRS; do re="$re|$d"; done
    re="(^|/)(${re#|})/"
    (cd "$root" 2>/dev/null && find . \( -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null) \
        | sed 's#^\./##' \
        | { grep -Ei "^\.github/workflows/[^/]+\.ya?ml$|$re" || true; } \
        | { grep -Ei "^\.github/workflows/|$NON_SHIPPED_MANIFEST_RE" || true; } \
        | LC_ALL=C sort
}

# Record the patterns and the manifest files left out, in the two properties
# build-prep.sh writes on the cdxgen path. The file list is capped at 50.
mark_sbom_excluded() {
    local file="$1" root="$2" list tmp
    [ -f "$file" ] || return 0
    non_shipped_enabled || return 0
    command -v jq >/dev/null 2>&1 || return 0
    list=$(non_shipped_manifests "$root")
    tmp="${file}.excluded.tmp"
    if jq --arg globs "$(non_shipped_globs)" --arg list "$list" '
        ($list | split("\n") | map(select(length > 0))) as $f
        | .metadata = (.metadata // {})
        | .metadata.properties = (((.metadata.properties // [])
              | map(select(.name != "bomlens:excluded-paths" and .name != "bomlens:excluded-manifests")))
            + [{name: "bomlens:excluded-paths", value: $globs}]
            + (if ($f | length) > 0
               then [{name: "bomlens:excluded-manifests",
                      value: (($f[0:50] | join(", "))
                              + (if ($f | length) > 50 then " (+\(($f | length) - 50) more)" else "" end))}]
               else [] end))' "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

detect_lang() {
    local d="$1" langs=""
    # Android: build.gradle with android plugin, or AndroidManifest.xml
    if grep -rqsE "com\.android\.(application|library)|namespace +['\"]" "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts 2>/dev/null \
       || find "$d" -maxdepth 3 -name AndroidManifest.xml 2>/dev/null | grep -q .; then
        echo "android"; return
    fi
    # iOS / Swift: SPM (Package.swift), CocoaPods (Podfile), or Xcode project
    if [ -f "$d/Package.swift" ] || [ -f "$d/Podfile" ] || [ -f "$d/Podfile.lock" ] \
       || ls "$d"/*.xcodeproj >/dev/null 2>&1 || ls "$d"/*.xcworkspace >/dev/null 2>&1; then
        echo "swift"; return
    fi
    [ -f "$d/Cargo.toml" ] && langs="$langs rust"
    [ -f "$d/go.mod" ] && langs="$langs go"
    [ -f "$d/Gemfile" ] && langs="$langs ruby"
    # Separate single-pattern globs: `ls a.gradle *.gradle.kts` exits non-zero when
    # one variant is absent, which would mis-skip gradle-only / kts-only projects.
    { [ -f "$d/pom.xml" ] || ls "$d"/*.gradle >/dev/null 2>&1 || ls "$d"/*.gradle.kts >/dev/null 2>&1; } && langs="$langs java"
    # setup.py/setup.cfg predate pyproject.toml and are still what a lot of
    # scientific Python ships: leaving them out made such a project detect as
    # "unknown", which sent it to the all-in-one image AND told the user no
    # manifest was found while the scan went on to resolve its dependencies.
    { [ -f "$d/requirements.txt" ] || [ -f "$d/pyproject.toml" ] \
      || [ -f "$d/setup.py" ] || [ -f "$d/setup.cfg" ] || [ -f "$d/Pipfile" ]; } && langs="$langs python"
    [ -f "$d/package.json" ] && langs="$langs node"
    [ -f "$d/composer.json" ] && langs="$langs php"
    { ls "$d"/*.csproj >/dev/null 2>&1 || ls "$d"/*.sln >/dev/null 2>&1; } && langs="$langs dotnet"
    # C/C++ with a package manager (Conan / vcpkg). cdxgen's all-in-one image
    # resolves these; raw CMake/Make C/C++ has no manifest and stays "unknown".
    { [ -f "$d/conanfile.txt" ] || [ -f "$d/conanfile.py" ] || [ -f "$d/vcpkg.json" ]; } && langs="$langs cpp"
    # shellcheck disable=SC2086
    set -- $langs
    if [ "$#" -eq 1 ]; then echo "$1"; elif [ "$#" -eq 0 ]; then echo "unknown"; else echo "mixed"; fi
}

img_for_lang() {
    case "$1" in
        rust)   echo "ghcr.io/cyclonedx/cdxgen-debian-rust:$CDXGEN_TAG" ;;
        go)     echo "ghcr.io/cyclonedx/cdxgen-debian-golang124:$CDXGEN_TAG" ;;
        ruby)   echo "ghcr.io/cyclonedx/cdxgen-debian-ruby34:$CDXGEN_TAG" ;;
        java)   echo "ghcr.io/cyclonedx/cdxgen-temurin-java21:$CDXGEN_TAG" ;;
        python) echo "ghcr.io/cyclonedx/cdxgen-python312:$CDXGEN_TAG" ;;
        node)   echo "ghcr.io/cyclonedx/cdxgen-node20:$CDXGEN_TAG" ;;
        php)    echo "ghcr.io/cyclonedx/cdxgen-debian-php84:$CDXGEN_TAG" ;;
        dotnet) echo "ghcr.io/cyclonedx/cdxgen-debian-dotnet9:$CDXGEN_TAG" ;;
        swift)  echo "ghcr.io/cyclonedx/cdxgen-debian-swift:$CDXGEN_TAG" ;;
        *)      echo "$CDXGEN_ALLINONE" ;;   # mixed / unknown
    esac
}

android_api() {
    local d="$1" api
    api=$(grep -rhoE "compileSdk(Version)?[ =]+[0-9]+" "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts 2>/dev/null \
          | grep -oE "[0-9]+" | head -1)
    echo "${api:-$ANDROID_API_DEFAULT}"
}
