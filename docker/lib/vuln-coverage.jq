# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# vuln-coverage.jq - which components a vulnerability check can reach.
#
# Shared by match-cpe-index.sh (which components the bundled CPE index is asked
# about) and scan-security.sh (which components no check could reach), so the
# two never disagree about what the index covers. Prepended to a filter with
# "$(cat vuln-coverage.jq)", the way license-flags.jq is.

# The purl type, lower-cased; "" when there is no purl.
def vc_purl_type:
  (.purl // "") | if startswith("pkg:") then (.[4:] | split("/")[0] | split("@")[0] | ascii_downcase) else "" end;

# A purl no advisory source Trivy reads is keyed on: none at all, `pkg:generic`,
# one that points at a source repository or project site (github, gitlab,
# bitbucket, git, sourceforge, gnu), or an OpenWrt package (opkg). For these a
# CPE is the only identifier a check can use.
def vc_no_ecosystem_purl:
  vc_purl_type | IN("", "generic", "github", "gitlab", "bitbucket", "git", "sourceforge", "gnu", "opkg");

# Offered to the bundled CPE index. A component with an ecosystem purl is left
# to the purl path: a CPE for a language package is derived from its name, and
# two projects that share a name do not share a version line. A purl
# synthesized from a container layer's os-release is the exception (see
# match-cpe-index.sh).
def vc_cpe_index_candidate:
  vc_no_ecosystem_purl or any(.properties[]?; .name == "bomlens:purlSource");

# A CPE the index can be asked about: the application part, in either form
# firmware-cpe-match.py parses.
def vc_app_cpe: (.cpe // "") | test("^cpe:(2\\.3:|/)a:");

# A version can be compared only if it holds a digit; placeholders such as
# UNKNOWN, "-" or "" cannot.
def vc_usable_version: (.version // "") | tostring | test("[0-9]");

# Distribution names Trivy reads an operating-system component as. Such a
# component tells Trivy which advisories to use for the packages; it is not
# itself a package to check. Any other operating-system component (busybox,
# OpenWrt) is software no advisory source keys on.
def vc_trivy_os_names:
  ["alpine", "alma", "almalinux", "amazon", "amzn", "azurelinux", "cbl-mariner",
   "mariner", "centos", "chainguard", "debian", "echo", "fedora", "opensuse",
   "opensuse-leap", "opensuse-tumbleweed", "opensuse.leap", "opensuse.tumbleweed",
   "sles", "sle-micro", "slem", "suse", "oracle", "ol", "photon", "redhat",
   "rhel", "rocky", "ubuntu", "wolfi", "bottlerocket", "minimos"];

# The components a vulnerability check is expected to cover.
def vc_in_scope:
  ((.type // "library") | IN("library", "application", "framework", "firmware", "operating-system"))
  and ((.name // "") != "")
  and ((.type == "operating-system" and ((.name // "") | ascii_downcase | IN(vc_trivy_os_names[]))) | not);

# Why no check could reach a component, or empty when one could.
#   no-version     there is no version to compare against an advisory
#   no-identifier  no ecosystem purl, and no CPE the index was asked about
def vc_unchecked_reason($cpe_matched):
  if (vc_usable_version | not) then "no-version"
  elif vc_no_ecosystem_purl and (($cpe_matched and vc_app_cpe) | not) then "no-identifier"
  else empty end;
