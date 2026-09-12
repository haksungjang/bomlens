// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Navigation model for the result shell — the single source of truth for the
 * left rail's sections, their grouping and which ones are AI-only.
 *
 * Kept free of React/JSX so the adaptation logic (`visibleGroups`) is unit
 * testable in isolation. The Sidebar component renders these descriptors; the
 * icons are plain lucide components referenced here by value.
 */
import {
  Boxes,
  Cpu,
  FileCheck2,
  FileInput,
  FileText,
  GitBranch,
  type LucideIcon,
  LayoutDashboard,
  Package,
  ScrollText,
  ShieldAlert,
} from "lucide-react";

/** Stable identifiers for each result section (used for routing/active state). */
export type SectionId =
  | "overview"
  | "components"
  | "dependencies"
  | "sourceTree"
  | "inputSbom"
  | "vulnerabilities"
  | "licenses"
  | "conformance"
  | "models"
  | "artifacts";

export interface NavSection {
  id: SectionId;
  /** i18n key under `nav.*` for the visible label. */
  labelKey: string;
  icon: LucideIcon;
  /**
   * Only shown for AI/ANALYZE scans (model components or AI-SBOM analysis).
   * Non-AI scans never see these so the rail stays honest per scan type.
   */
  aiOnly?: boolean;
  /**
   * Shown only when the scan actually produced this section's data (e.g. a
   * dependency graph or a ScanCode source tree). Omit for always-present
   * sections. Mirrors the conditional tabs the classic dashboard rendered.
   */
  requires?: (ctx: ScanContext) => boolean;
}

export interface NavGroup {
  id: string;
  /** i18n key under `nav.group.*`. */
  labelKey: string;
  sections: NavSection[];
}

/**
 * Context that drives rail adaptation. `mode` is the backend MODE string
 * (SOURCE/IMAGE/ROOTFS/FIRMWARE/ANALYZE…), null before any scan. `isAiScan`
 * gates the AI surfaces (wired in Phase 3; false until then). The `has*` flags
 * mirror the data-conditional tabs the classic dashboard rendered.
 */
export interface ScanContext {
  mode: string | null;
  isAiScan: boolean;
  /** A CycloneDX SBOM artifact exists, so the dependency graph can be built. */
  hasDependencies: boolean;
  /** A ScanCode artifact exists, so the source tree can be shown. */
  hasSourceTree: boolean;
  /** The scan's input was an SBOM and its header summary was captured. */
  hasInputSbom: boolean;
  /**
   * An SBOM conformance report exists (ANALYZE produced format/G7 checks), so
   * the conformance section applies — regardless of AI content.
   */
  hasConformance: boolean;
}

export const EMPTY_SCAN: ScanContext = {
  mode: null,
  isAiScan: false,
  hasDependencies: false,
  hasSourceTree: false,
  hasInputSbom: false,
  hasConformance: false,
};

/**
 * The full rail, grouped. `visibleGroups` filters out AI-only sections for
 * non-AI scans and data-gated sections whose data is absent. Order here is the
 * on-screen order.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    id: "inventory",
    labelKey: "nav.group.inventory",
    sections: [
      { id: "overview", labelKey: "nav.overview", icon: LayoutDashboard },
      { id: "components", labelKey: "nav.components", icon: Boxes },
      {
        id: "dependencies",
        labelKey: "nav.dependencies",
        icon: GitBranch,
        requires: (c) => c.hasDependencies,
      },
      {
        id: "sourceTree",
        labelKey: "nav.sourceTree",
        icon: FileText,
        requires: (c) => c.hasSourceTree,
      },
      // The scanned input, when that input was itself an SBOM: what the
      // supplier sent, before the conversion to CycloneDX that everything else
      // on screen describes. Sits beside the source tree because it answers the
      // same question for a different kind of scan — what did we look at?
      {
        id: "inputSbom",
        labelKey: "nav.inputSbom",
        icon: FileInput,
        requires: (c) => c.hasInputSbom,
      },
    ],
  },
  // Security and compliance are split because they are read by different people
  // at different moments: a CVE list is triaged against a patch schedule, while
  // licence obligations are settled once per release. Grouping them together
  // made whoever needed one of them scan past the other.
  {
    id: "security",
    labelKey: "nav.group.security",
    sections: [
      { id: "vulnerabilities", labelKey: "nav.vulnerabilities", icon: ShieldAlert },
    ],
  },
  {
    id: "compliance",
    labelKey: "nav.group.compliance",
    sections: [
      { id: "licenses", labelKey: "nav.licenses", icon: ScrollText },
      // A conformance report now exists for every mode (a mandatory checklist
      // run against whatever SBOM the scan ends with), but it is only a
      // verdict a reader should see as a screen when the document being
      // graded was actually submitted by someone (hasInputSbom — ANALYZE on
      // a supplier's SBOM, AI SBOM included). For a plain generated SBOM the
      // same report stays a file in Artifacts — mandatory checks like
      // "transitive edges present" or "PURL coverage" are real data-quality
      // signals, but tautological ones (spec-version, timestamp, tool info)
      // will pass on any healthy pipeline run, and a binary-derived scan
      // (ROOTFS/IMAGE/FIRMWARE) can fail name-version permanently for reasons
      // that are not a defect — none of that belongs in the same sidebar list
      // as facts about the scanned software. A self-generated AI SBOM's G7
      // minimum-element rollup is the one exception worth surfacing on its
      // own: it grades the model PUBLISHER's own disclosure (BomLens only
      // transcribes the model card), a real finding rather than a self-grade
      // — but it lives on Models & datasets (AiSummaryCard + this section's
      // own CheckGroup rendering, reused there), not here.
      //
      // Deliberately NOT `mode === "ANALYZE"`: ScanContext.mode only reflects
      // the run that is currently streaming (server.py's scan_detail() sends
      // "mode": None for a re-opened past scan), so gating on it would hide
      // this section for a supplier's ANALYZE scan the moment it's reopened
      // from Recent, refreshed, or viewed on the published demo site.
      // hasInputSbom is derived from an artifact file and survives re-open.
      {
        id: "conformance",
        labelKey: "nav.conformance",
        icon: FileCheck2,
        requires: (c) => c.hasConformance && c.hasInputSbom,
      },
    ],
  },
  {
    id: "ai",
    labelKey: "nav.group.ai",
    sections: [
      { id: "models", labelKey: "nav.models", icon: Cpu, aiOnly: true },
    ],
  },
  {
    id: "outputs",
    labelKey: "nav.group.outputs",
    sections: [
      { id: "artifacts", labelKey: "nav.artifacts", icon: Package },
    ],
  },
];

/**
 * Groups to render for the given scan: AI-only sections removed for non-AI
 * scans, data-gated sections removed when their data is absent, and any group
 * left empty dropped entirely.
 */
export function visibleGroups(ctx: ScanContext): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    sections: group.sections.filter(
      (s) => (!s.aiOnly || ctx.isAiScan) && (!s.requires || s.requires(ctx)),
    ),
  })).filter((group) => group.sections.length > 0);
}

/** Flat list of visible section ids, in rail order — handy for default/active. */
export function visibleSectionIds(ctx: ScanContext): SectionId[] {
  return visibleGroups(ctx).flatMap((g) => g.sections.map((s) => s.id));
}

/** A past scan as shown in the top bar's Recent menu (lightweight link shape). */
export interface RecentScanLink {
  id: string;
  label: string;
  topSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
}

