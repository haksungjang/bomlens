// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FileCheck2, Loader2, PencilLine, TriangleAlert } from "lucide-react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
import type { Spdx3Summary } from "@/lib/api";
import { bandSegments, type CheckElement, type FieldStatus, type Spdx3Check } from "@/lib/aiDeclaration";
import { cn } from "@/lib/utils";

const SEGMENT_COLOR: Record<string, string> = {
  filled: "bg-risk-low",
  optional: "bg-muted-foreground/40",
  judgment: "bg-risk-medium",
  missingRequired: "bg-risk-critical",
};

/**
 * The SPDX 3.0.1 AI document's state on the Models & datasets screen: draft or
 * complete, how its fields were filled, and the way into the questions that
 * fill the rest. A scan from before the document existed gets a button that
 * writes it instead.
 */
export function Spdx3StatusBand({
  summary,
  available,
  busy,
  onFill,
  onWrite,
  focusFill,
}: {
  summary: Spdx3Summary | null | undefined;
  /** This server can write the document and save a declaration. */
  available: boolean;
  /** A write or a save is in flight. */
  busy: boolean;
  onFill: () => void;
  onWrite: () => void;
  /** The question flow just closed: give focus back to the button that opened it. */
  focusFill?: boolean;
}) {
  const { t } = useTranslation();
  const fillRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (focusFill) fillRef.current?.focus();
  }, [focusFill]);

  if (!summary) {
    return (
      <Card data-testid="spdx3-band">
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
          <div className="min-w-0">
            <div className="text-sm font-semibold">{t("spdx3.band.title")}</div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {available ? t("spdx3.band.none") : t("spdx3.band.unavailable")}
            </p>
          </div>
          {available && (
            <Button variant="outline" size="sm" onClick={onWrite} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileCheck2 className="h-4 w-4" />}
              {t("spdx3.band.write")}
            </Button>
          )}
        </CardContent>
      </Card>
    );
  }

  const segments = bandSegments(summary.counts);
  const total = segments.reduce((n, s) => n + s.count, 0) || 1;
  const missing = summary.counts.missingRequired ?? 0;
  const refused = summary.declaration?.state === "refused";

  return (
    <Card data-testid="spdx3-band">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">{t("spdx3.band.title")}</span>
            {summary.draft ? (
              <Badge tone="warning">{t("spdx3.draft")}</Badge>
            ) : (
              <Badge tone="success">{t("spdx3.complete")}</Badge>
            )}
          </div>
          {available && (
            <Button ref={fillRef} size="sm" onClick={onFill} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PencilLine className="h-4 w-4" />}
              {t("spdx3.band.fill")}
            </Button>
          )}
        </div>
        <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden>
          {segments.map((s) =>
            s.count > 0 ? (
              <div
                key={s.key}
                className={SEGMENT_COLOR[s.key]}
                style={{ width: `${(s.count / total) * 100}%` }}
              />
            ) : null,
          )}
        </div>
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
          {segments.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5" data-segment={s.key}>
              <span className={cn("h-2 w-2 rounded-full", SEGMENT_COLOR[s.key])} aria-hidden />
              {t(`spdx3.segment.${s.key}`)}
              <span className="tabular-nums font-medium">{s.count}</span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">
          {summary.draft ? t("spdx3.band.draftNote", { count: missing }) : t("spdx3.band.completeNote")}
        </p>
        {refused && (
          <div
            role="status"
            className="space-y-1 rounded-md border border-warning/40 bg-warning-surface p-3 text-xs text-warning dark:bg-warning-surface/15"
          >
            <div className="flex items-center gap-1.5 font-medium">
              <TriangleAlert className="h-3.5 w-3.5" aria-hidden />
              {t("spdx3.band.refused")}
            </div>
            <ul className="list-disc space-y-0.5 pl-5 font-mono">
              {(summary.declaration?.reasons ?? []).slice(0, 5).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

const STATUS_BADGE: Record<FieldStatus, { tone?: "low" | "info" | "critical" | "medium"; key: string }> = {
  auto: { tone: "low", key: "auto" },
  declared: { tone: "info", key: "declared" },
  noAssertion: { key: "noAssertion" },
  missingRequired: { tone: "critical", key: "missingRequired" },
  judgment: { tone: "medium", key: "judgment" },
  optional: { key: "optional" },
  omitted: { key: "omitted" },
  review: { key: "review" },
};

export function Spdx3StatusBadge({ status }: { status: FieldStatus }) {
  const { t } = useTranslation();
  const b = STATUS_BADGE[status];
  return b.tone ? (
    <Badge tone={b.tone}>{t(`spdx3.status.${b.key}`)}</Badge>
  ) : (
    <Badge variant="muted">{t(`spdx3.status.${b.key}`)}</Badge>
  );
}

/** The translation namespace for an element type's field names. */
export function fieldNamespace(type: string): "document" | "model" | "dataset" {
  return type === "CreationInfo" ? "document" : type === "ai_AIPackage" ? "model" : "dataset";
}

const SHOWN: FieldStatus[] = ["auto", "declared", "noAssertion", "missingRequired", "judgment"];

/**
 * One element's fields in the SPDX 3.0.1 document: the value and where it came
 * from. Optional fields nobody filled are counted under the table instead of
 * listed, so the rows that need attention are not lost among them.
 */
type ExtraRow = { key: string; label: string; value: string | null; status: FieldStatus; statusLabel?: string };

export function Spdx3FieldTable({
  element,
  extraRows = [],
  trailingRows = [],
}: {
  element: CheckElement;
  /** Rows from the document as a whole (its author), shown before the fields. */
  extraRows?: ExtraRow[];
  /** Rows from a relationship (how the model used a dataset), shown after them. */
  trailingRows?: ExtraRow[];
}) {
  const { t } = useTranslation();
  const ns = fieldNamespace(element.type);
  const rows = element.fields.filter((f) => SHOWN.includes(f.status) || (f.status === "optional" && f.display));
  const hidden = element.fields.filter((f) => f.status === "optional" && !f.display).length;
  return (
    <div className="space-y-1">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-left text-xs">
          <thead className="border-b bg-muted/40 text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.field")}</th>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.value")}</th>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.status")}</th>
            </tr>
          </thead>
          <tbody>
            {extraRows.map((r) => <ExtraTableRow key={r.key} row={r} />)}
            {rows.map((f) => (
              <tr key={f.id} className="border-b last:border-0" data-field={f.id}>
                <td className="px-3 py-2 align-top">{t(`aiDecl.${ns}.${f.id}.label`, { defaultValue: f.id })}</td>
                <td className="px-3 py-2 align-top break-all">
                  {f.display ?? <span className="text-muted-foreground">{t("spdx3.table.notFilled")}</span>}
                  {f.meaning === "huggingface-publisher" && (
                    <span className="ml-1 text-muted-foreground">{t("spdx3.table.hubPublisher")}</span>
                  )}
                </td>
                <td className="px-3 py-2 align-top">
                  <Spdx3StatusBadge status={f.status} />
                </td>
              </tr>
            ))}
            {trailingRows.map((r) => <ExtraTableRow key={r.key} row={r} />)}
          </tbody>
        </table>
      </div>
      {hidden > 0 && <p className="text-xs text-muted-foreground">{t("spdx3.table.optionalHidden", { count: hidden })}</p>}
    </div>
  );
}

function ExtraTableRow({ row }: { row: ExtraRow }) {
  const { t } = useTranslation();
  return (
    <tr className="border-b last:border-0">
      <td className="px-3 py-2 align-top">{row.label}</td>
      <td className="px-3 py-2 align-top break-all">
        {row.value ?? <span className="text-muted-foreground">{t("spdx3.table.notFilled")}</span>}
      </td>
      <td className="px-3 py-2 align-top">
        {row.statusLabel ? <Badge variant="muted">{row.statusLabel}</Badge> : <Spdx3StatusBadge status={row.status} />}
      </td>
    </tr>
  );
}

/** The SPDX 3.0.1 view of the scan: the model's fields (with the document's
 *  author and the card's datasets), then each dataset's, folded. */
export function Spdx3Fields({ check }: { check: Spdx3Check }) {
  const { t } = useTranslation();
  const doc = check.elements.find((e) => e.type === "CreationInfo");
  const model = check.elements.find((e) => e.type === "ai_AIPackage");
  const datasets = check.elements.filter((e) => e.type === "dataset_DatasetPackage");
  const author = doc?.fields.find((f) => f.id === "createdBy");
  const extra = author
    ? [{ key: "createdBy", label: t("aiDecl.document.createdBy.label"), value: author.display ?? null, status: author.status }]
    : [];
  // Only the datasets the card names; one the publisher added without a role
  // carries a different note and is not "named on the card".
  const roleOpen = check.relationships.filter(
    (r) => r.status === "review" && r.note === "card-declared dataset, role not stated",
  );
  const roleRows = roleOpen.length
    ? [
        {
          key: "roles",
          label: t("spdx3.table.cardDatasets"),
          value: roleOpen.map((r) => r.toLabel).filter(Boolean).join(", ") || null,
          status: "review" as FieldStatus,
          statusLabel: t("spdx3.table.roleOpen"),
        },
      ]
    : [];
  return (
    <div className="space-y-3">
      {model && (
        <Card>
          <CardContent className="space-y-2 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="text-sm font-semibold">{model.label}</span>
              <span className="text-xs text-muted-foreground">{t("spdx3.table.caption")}</span>
            </div>
            <Spdx3FieldTable element={model} extraRows={extra} trailingRows={roleRows} />
          </CardContent>
        </Card>
      )}
      {!model && doc && datasets[0] && (
        <Card>
          <CardContent className="space-y-2 p-4">
            <span className="text-sm font-semibold">{datasets[0].label}</span>
            <Spdx3FieldTable element={datasets[0]} extraRows={extra} />
          </CardContent>
        </Card>
      )}
      {datasets.slice(model ? 0 : 1).length > 0 && (
        <Disclosure summary={<span className="text-sm font-medium">{t("spdx3.table.datasetFields", { count: datasets.length - (model ? 0 : 1) })}</span>}>
          <div className="mt-2 space-y-3">
            {datasets.slice(model ? 0 : 1).map((d) => (
              <div key={d.declarationKey ?? d.label} className="space-y-1">
                <div className="text-xs font-semibold">{d.label}</div>
                <Spdx3FieldTable element={d} />
              </div>
            ))}
          </div>
        </Disclosure>
      )}
      <p className="text-xs text-muted-foreground">{t("spdx3.table.notLegalAdvice")}</p>
    </div>
  );
}
