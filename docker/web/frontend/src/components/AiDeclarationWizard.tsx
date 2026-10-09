// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Check, Loader2, Plus, Trash2, X } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import type { Spdx3Failure } from "@/lib/api";
import {
  AGENT_TYPES,
  DATASET_MORE_FIELDS,
  ROLES,
  SOURCE_RELATIONS,
  dateToDeclared,
  declaredToDate,
  isEmpty,
  isHubId,
  issues as findIssues,
  judgmentFields,
  LONG_TEXT,
  MODEL_USE_FIELDS,
  modelMainFields,
  MODEL_LICENSE_FIELD,
  remainingRequired,
  saveBlockers,
  stepOf,
  stepsFor,
  toFile,
  TRAINING_FIELDS,
  type Agent,
  type Declaration,
  type DictEntry,
  type FieldIndex,
  type Issue,
  type MapField,
  type SourceEntry,
  type Spdx3Check,
  type StepId,
  type Value,
} from "@/lib/aiDeclaration";
import { useAiDeclaration, type Target } from "@/lib/useAiDeclaration";
import { cn } from "@/lib/utils";

type Ns = "document" | "model" | "dataset";

const textAreaClass =
  "flex min-h-[4.5rem] w-full rounded-lg border border-input bg-background px-3 py-2 text-sm ring-offset-background " +
  "placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

const chipClass = (on: boolean) =>
  cn(
    "rounded-full border px-3 py-1 text-sm transition-colors duration-fast ease-out-soft",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
    on ? "border-foreground bg-foreground text-background" : "border-input hover:bg-muted",
  );

/**
 * A row of choices. As a single choice it follows the radio-group pattern: one
 * Tab stop, the arrow keys move and select, and choosing the selected option
 * again clears it (every one of these questions may be left unanswered). As a
 * multiple choice each option is a toggle button.
 */
function Choices({
  options,
  selected,
  onPick,
  labelOf,
  multi,
  labelledBy,
  describedBy,
}: {
  options: string[];
  selected: string[];
  onPick: (value: string) => void;
  labelOf: (value: string) => string;
  multi?: boolean;
  labelledBy: string;
  describedBy?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  if (multi) {
    return (
      <div role="group" aria-labelledby={labelledBy} aria-describedby={describedBy} className="flex flex-wrap gap-2">
        {options.map((o) => (
          <button key={o} type="button" aria-pressed={selected.includes(o)} onClick={() => onPick(o)} className={chipClass(selected.includes(o))}>
            {labelOf(o)}
          </button>
        ))}
      </div>
    );
  }
  const current = options.findIndex((o) => selected.includes(o));
  const onKey = (e: KeyboardEvent, i: number) => {
    const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = (i + step + options.length) % options.length;
    refs.current[next]?.focus();
    if (!selected.includes(options[next])) onPick(options[next]);
  };
  return (
    <div role="radiogroup" aria-labelledby={labelledBy} aria-describedby={describedBy} className="flex flex-wrap gap-2">
      {options.map((o, i) => {
        const on = selected.includes(o);
        return (
          <button
            key={o}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={i === (current >= 0 ? current : 0) ? 0 : -1}
            onClick={() => onPick(o)}
            onKeyDown={(e) => onKey(e, i)}
            className={chipClass(on)}
          >
            {labelOf(o)}
          </button>
        );
      })}
    </div>
  );
}

function AgentInput({
  value,
  onChange,
  id,
  label,
  describedBy,
  required,
}: {
  value: Agent | null;
  onChange: (v: Agent) => void;
  id?: string;
  /** Used when no <label> points at the input (a second row of a list). */
  label?: string;
  describedBy?: string;
  required?: boolean;
}) {
  const { t } = useTranslation();
  const v = value ?? { type: "Organization", name: "" };
  return (
    <div className="flex gap-2">
      <Input
        id={id}
        aria-label={label}
        aria-describedby={describedBy}
        aria-required={required || undefined}
        value={v.name}
        placeholder={t("aiDecl.agentPlaceholder")}
        onChange={(e) => onChange({ type: v.type || "Organization", name: e.target.value })}
      />
      <Select
        aria-label={t("aiDecl.agentType")}
        value={v.type || "Organization"}
        onChange={(e) => onChange({ type: e.target.value, name: v.name })}
        className="h-10 shrink-0"
      >
        {AGENT_TYPES.map((a) => (
          <option key={a} value={a}>
            {t(`aiDecl.agent.${a}`)}
          </option>
        ))}
      </Select>
    </div>
  );
}

/** Rows that can be added and removed. An empty row stays while it is being
 *  typed in; empty rows are left out when the declaration is saved. */
function ListEditor<T>({
  items,
  blank,
  onChange,
  render,
  addLabel,
  removeLabel,
}: {
  items: T[];
  blank: T;
  onChange: (items: T[]) => void;
  render: (item: T, set: (v: T) => void, i: number) => ReactNode;
  addLabel: string;
  removeLabel: (i: number) => string;
}) {
  const rows = items.length ? items : [blank];
  return (
    <div className="space-y-2">
      {rows.map((it, i) => (
        <div key={i} className="flex items-start gap-2">
          <div className="min-w-0 flex-1">{render(it, (v) => onChange(rows.map((x, j) => (j === i ? v : x))), i)}</div>
          {rows.length > 1 && (
            <Button variant="ghost" size="sm" aria-label={removeLabel(i)} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={() => onChange([...rows, blank])}>
        <Plus className="h-3.5 w-3.5" />
        {addLabel}
      </Button>
    </div>
  );
}

/** One question: the label, its input by the field's type, and what is wrong.
 *  A problem shows once the person has left the field, not while typing. */
function Field({
  ns,
  field,
  value,
  problem,
  onChange,
  showProblems,
}: {
  ns: Ns;
  field: MapField;
  value: Value | undefined;
  problem?: Issue["problem"];
  onChange: (v: Value) => void;
  /** Show the problem even if the field was not left yet (on the review step's
   *  way back here, for instance). */
  showProblems?: boolean;
}) {
  const { t } = useTranslation();
  const id = useId();
  const labelId = `${id}-label`;
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const [touched, setTouched] = useState(false);
  const key = `aiDecl.${ns}.${field.id}`;
  const label = t(`${key}.label`, { defaultValue: field.id });
  const required = field.min >= 1;
  const hint = t(`${key}.hint`, { defaultValue: "" });
  const example = t(`${key}.example`, { defaultValue: "" });
  // Agents, dates and addresses have no "unknown": empty fails validation.
  const noUnknown = ["Agent", "DateTime", "anyURI"].includes(field.type);
  const showMissing = required && noUnknown && isEmpty(value);
  const showProblem = Boolean(problem && problem !== "required" && (touched || showProblems));
  const describedBy = [hint && hintId, (showMissing || showProblem) && errId].filter(Boolean).join(" ") || undefined;
  const isList = field.max === "*" && !field.enum;
  const rowLabel = (i: number) => `${label} ${i + 1}`;

  let input: ReactNode;
  if (field.enum) {
    const opts = field.enum.filter((o) => o !== "noAssertion" || field.noAssertion);
    // The vocabulary's own "unknown" goes last, where a person looks for it.
    opts.sort((a, b) => Number(a === "noAssertion") - Number(b === "noAssertion"));
    const many = field.max === "*";
    const sel = many ? ((value as string[] | undefined) ?? []) : value ? [value as string] : [];
    input = (
      <Choices
        options={opts}
        selected={sel}
        multi={many}
        labelledBy={labelId}
        describedBy={describedBy}
        labelOf={(o) => t(`aiDecl.enum.${o}`, { defaultValue: o })}
        onPick={(o) => {
          if (!many) return onChange(sel.includes(o) ? "" : o);
          if (o === "noAssertion") return onChange(sel.includes(o) ? [] : [o]);
          const rest = sel.filter((x) => x !== "noAssertion");
          onChange(rest.includes(o) ? rest.filter((x) => x !== o) : [...rest, o]);
        }}
      />
    );
  } else if (field.type === "DateTime") {
    input = (
      <Input
        id={id}
        type="date"
        className="max-w-[12rem]"
        aria-describedby={describedBy}
        aria-required={required || undefined}
        value={declaredToDate(value)}
        onChange={(e) => onChange(dateToDeclared(e.target.value))}
      />
    );
  } else if (field.type === "Agent" && field.max === "*") {
    input = (
      <ListEditor<Agent>
        items={(value as Agent[] | undefined) ?? []}
        blank={{ type: "Organization", name: "" }}
        addLabel={t("aiDecl.addAgent")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(a, set, i) => (
          <AgentInput
            value={a}
            onChange={set}
            label={rowLabel(i)}
            describedBy={i === 0 ? describedBy : undefined}
            required={required && i === 0}
          />
        )}
      />
    );
  } else if (field.type === "Agent") {
    input = (
      <AgentInput
        id={id}
        value={(value as Agent | null) ?? null}
        onChange={(v) => onChange(v)}
        describedBy={describedBy}
        required={required}
      />
    );
  } else if (field.type === "DictionaryEntry") {
    input = (
      <ListEditor<DictEntry>
        items={(value as DictEntry[] | undefined) ?? []}
        blank={{ key: "", value: "" }}
        addLabel={t("aiDecl.addPair")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(e, set, i) => (
          <div className="flex gap-2">
            <Input
              aria-label={`${rowLabel(i)}: ${t("aiDecl.pairKey")}`}
              aria-describedby={i === 0 ? describedBy : undefined}
              placeholder={t("aiDecl.pairKey")}
              value={e.key}
              onChange={(x) => set({ ...e, key: x.target.value })}
            />
            <Input
              aria-label={`${rowLabel(i)}: ${t("aiDecl.pairValue")}`}
              placeholder={t("aiDecl.pairValue")}
              value={e.value}
              onChange={(x) => set({ ...e, value: x.target.value })}
            />
          </div>
        )}
      />
    );
  } else if (field.max === "*") {
    input = (
      <ListEditor<string>
        items={(value as string[] | undefined) ?? []}
        blank=""
        addLabel={t("aiDecl.addLine")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(s, set, i) => (
          <Input
            aria-label={rowLabel(i)}
            aria-describedby={i === 0 ? describedBy : undefined}
            placeholder={i === 0 && example ? t("aiDecl.examplePrefix", { example }) : undefined}
            value={s}
            onChange={(e) => set(e.target.value)}
          />
        )}
      />
    );
  } else if (LONG_TEXT.has(field.id)) {
    input = (
      <textarea
        id={id}
        className={textAreaClass}
        aria-describedby={describedBy}
        value={(value as string | undefined) ?? ""}
        placeholder={example ? t("aiDecl.examplePrefix", { example }) : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  } else {
    input = (
      <Input
        id={id}
        type={field.type === "anyURI" ? "url" : "text"}
        aria-describedby={describedBy}
        aria-required={required || undefined}
        value={(value as string | undefined) ?? ""}
        placeholder={example ? t("aiDecl.examplePrefix", { example }) : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }

  return (
    <div
      className="space-y-1.5"
      data-question={`${ns}.${field.id}`}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setTouched(true);
      }}
    >
      <div className="flex items-center gap-2">
        {field.enum || isList ? (
          <span id={labelId} className="text-sm font-medium">
            {label}
          </span>
        ) : (
          <label id={labelId} htmlFor={id} className="text-sm font-medium">
            {label}
          </label>
        )}
        {required && <Badge variant="muted">{t("g7.required")}</Badge>}
      </div>
      {input}
      {hint && (
        <p id={hintId} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
      <div id={errId} aria-live="polite">
        {showProblem ? (
          <p className="text-xs text-risk-critical-fg">{t(`aiDecl.problem.${problem}`)}</p>
        ) : showMissing ? (
          <p className="text-xs text-risk-critical-fg">{t("aiDecl.requiredFailsValidation")}</p>
        ) : null}
      </div>
    </div>
  );
}

/**
 * The questions that fill the SPDX 3.0.1 document's open fields: the base
 * models' revisions, the model, the data, and the calls only the publisher can
 * make. It asks only what the scan left open (the server's empty declaration
 * lists exactly that) and shows what the scan already filled as read-only.
 */
/**
 * The sources of one dataset: those already on record (traced from its card,
 * read-only) and those the publisher adds, by hub id (read from the hub at the
 * next scan) or named in words with the licence they know. There is no
 * "unknown" here: a licence left empty is recorded as not stated.
 */
function SourcesEditor({
  name,
  onRecord,
  sources,
  problems,
  allowHub,
  showProblems,
  onChange,
}: {
  name: string;
  onRecord: string[];
  sources: SourceEntry[];
  problems: Issue["problem"][];
  /** Data the hub does not hold takes sources named in words only. */
  allowHub: boolean;
  showProblems?: boolean;
  onChange: (v: SourceEntry[]) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [touched, setTouched] = useState(false);
  const set = (i: number, v: SourceEntry) => onChange(sources.map((x, j) => (j === i ? v : x)));
  const shown = touched || showProblems ? problems : [];
  const errId = `${id}-err`;
  const row = (i: number) => i + 1;
  return (
    <div
      role="group"
      aria-labelledby={`${id}-label`}
      aria-describedby={shown.length ? errId : undefined}
      className="space-y-2 rounded-md border border-dashed p-3"
      data-sources={name}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setTouched(true);
      }}
    >
      <div id={`${id}-label`} className="text-sm font-medium">
        {t("aiDecl.sources.label")}
      </div>
      <p className="text-xs text-muted-foreground">
        {onRecord.length ? t("aiDecl.sources.onRecord", { list: onRecord.join(", ") }) : t("aiDecl.sources.none")}
      </p>
      {sources.map((src, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2" data-source-row={i}>
          {src.ref !== undefined ? (
            <span className="font-mono text-sm">{src.ref.replace(/^huggingface:/, "")}</span>
          ) : (
            <>
              <Input
                className="min-w-[10rem] flex-1"
                aria-label={t("aiDecl.sources.nameN", { n: row(i) })}
                aria-invalid={shown.length > 0 || undefined}
                aria-describedby={shown.length ? errId : undefined}
                placeholder={t("aiDecl.sources.name")}
                value={src.name ?? ""}
                onChange={(e) => set(i, { ...src, name: e.target.value })}
              />
              <Input
                className="w-44"
                aria-label={t("aiDecl.sources.licenseN", { n: row(i) })}
                aria-invalid={shown.length > 0 || undefined}
                aria-describedby={shown.length ? errId : undefined}
                placeholder={t("aiDecl.sources.licensePlaceholder")}
                value={src.license ?? ""}
                onChange={(e) => set(i, { ...src, license: e.target.value })}
              />
            </>
          )}
          <Select
            aria-label={t("aiDecl.sources.relationN", { n: row(i) })}
            value={src.relation}
            onChange={(e) => set(i, { ...src, relation: e.target.value as SourceEntry["relation"] })}
            className="h-10"
          >
            {SOURCE_RELATIONS.map((r) => (
              <option key={r} value={r}>
                {t(`aiDecl.sources.rel.${r}`)}
              </option>
            ))}
          </Select>
          <Button
            variant="ghost"
            size="sm"
            aria-label={t("aiDecl.removeRow", {
              name: src.ref?.replace(/^huggingface:/, "") || src.name || t("aiDecl.sources.nameN", { n: row(i) }),
            })}
            onClick={() => onChange(sources.filter((_, j) => j !== i))}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      ))}
      {allowHub && (
        <AddById
          label={t("aiDecl.sources.addHub")}
          placeholder={t("aiDecl.examplePrefix", { example: "allenai/c4" })}
          button={t("aiDecl.sources.addButton")}
          onAdd={(hubId) => {
            const ref = `huggingface:${hubId}`;
            const lower = hubId.toLowerCase();
            // Already a declared source, or already on record from the card.
            if (sources.some((x) => x.ref?.toLowerCase() === ref.toLowerCase())) return;
            if (onRecord.some((x) => x.toLowerCase() === lower)) return;
            onChange([...sources, { ref, relation: "extended" }]);
          }}
        />
      )}
      <Button variant="outline" size="sm" onClick={() => onChange([...sources, { name: "", license: "", relation: "other" }])}>
        <Plus className="h-3.5 w-3.5" />
        {t("aiDecl.sources.addNamed")}
      </Button>
      <div id={errId} aria-live="polite">
        {[...new Set(shown)].map((p) => (
          <p key={p} className="text-xs text-risk-critical-fg">
            {t(`aiDecl.problem.${p}`)}
          </p>
        ))}
      </div>
    </div>
  );
}

/** Adds an id (a base model, a hub dataset) from a text box. */
function AddById({
  label,
  placeholder,
  button,
  onAdd,
}: {
  label: string;
  placeholder: string;
  button: string;
  onAdd: (id: string) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [value, setValue] = useState("");
  const v = value.trim();
  const bad = v !== "" && !isHubId(v);
  const add = () => {
    if (!v || bad) return;
    onAdd(v);
    setValue("");
  };
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <div className="flex gap-2">
        <Input
          id={id}
          value={value}
          placeholder={placeholder}
          aria-describedby={`${id}-err`}
          aria-invalid={bad || undefined}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button variant="outline" onClick={add} disabled={!v || bad}>
          <Plus className="h-3.5 w-3.5" />
          {button}
        </Button>
      </div>
      <div id={`${id}-err`} aria-live="polite">
        {bad && <p className="text-xs text-risk-critical-fg">{t("aiDecl.problem.hubId")}</p>}
      </div>
    </div>
  );
}

export function AiDeclarationWizard({
  title,
  index,
  initial,
  initialStep,
  check,
  onCancel,
  onSave,
  onDraft,
  mode = "fill",
  authorFromScan: authorGiven,
}: {
  title: string;
  index: FieldIndex;
  initial: Declaration;
  /** Where to reopen an answer set kept from an earlier visit. */
  initialStep?: StepId;
  check: Spdx3Check | null;
  onCancel: () => void;
  /** Resolves null when saved, or the failure to show. */
  onSave: (file: Declaration) => Promise<Spdx3Failure | null>;
  /** Called with the answers as they change, so leaving the section and coming
   *  back does not lose them. */
  onDraft?: (decl: Declaration, step: StepId) => void;
  /** "fill": the open fields of a finished scan. "create": a model described
   *  from the declaration alone, before any scan (base models and datasets
   *  are added here, and saving starts the scan). */
  mode?: "fill" | "create";
  /** The scan names the document's author itself (--sbom-author), so the
   *  question is not asked. Read from the check when not given. */
  authorFromScan?: boolean;
}) {
  const { t } = useTranslation();
  const create = mode === "create";
  const steps = useMemo(() => stepsFor(index, initial, create), [index, initial, create]);
  const [state, dispatch] = useAiDeclaration(
    initial,
    initialStep && steps.includes(initialStep) ? initialStep : steps[0],
  );
  const { decl, step } = state;
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<Spdx3Failure | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  // Each step (and the flow's opening) moves focus to its question, so a
  // screen reader announces it and the keyboard starts at the top.
  useEffect(() => {
    heading.current?.focus();
  }, [step]);

  useEffect(() => {
    onDraft?.(decl, step);
  }, [decl, step, onDraft]);

  const authorFromScan =
    authorGiven ??
    check?.elements.find((e) => e.type === "CreationInfo")?.fields.find((f) => f.id === "createdBy")?.status === "auto";
  const all = findIssues(index, decl, authorFromScan);
  const blockers = saveBlockers(all);
  const remaining = remainingRequired(all);
  const totalRequired = Math.max(remaining, remainingRequired(findIssues(index, initial, authorFromScan)));
  const problemAt = (where: string, field: string) => all.find((i) => i.where === where && i.field === field)?.problem;
  const hasIssueIn = (where: string, fields: string[]) => all.some((i) => i.where === where && fields.includes(i.field));
  const set = (target: Target, field: string, value: Value) => dispatch({ type: "set", target, field, value });
  // Back from the review step, show every problem at once.
  const [reviewed, setReviewed] = useState(false);

  const stepIndex = steps.indexOf(step);
  const go = (s: StepId) => {
    if (step === "preview") setReviewed(true);
    dispatch({ type: "step", step: s });
  };

  const modelField = (id: string) => {
    const f = index.ai_AIPackage[id];
    return f ? (
      <Field
        key={id}
        ns="model"
        field={f}
        value={decl.model?.[id] as Value | undefined}
        problem={problemAt("model", id)}
        showProblems={reviewed}
        onChange={(v) => set({ kind: "model" }, id, v)}
      />
    ) : null;
  };

  const autoOf = (key: string | undefined, id: string) =>
    check?.elements.find((e) => e.declarationKey === key)?.fields.find((f) => f.id === id && f.display)?.display;

  const save = async () => {
    setSaving(true);
    setFailure(null);
    const res = await onSave(toFile(decl, create));
    setSaving(false);
    if (res) setFailure(res);
  };

  let body: ReactNode;
  let why: string;
  if (step === "base") {
    why = create ? "baseCreate" : "base";
    body = (
      <div className="space-y-3">
        {create && (
          <Card>
            <CardContent className="p-4">
              <AddById
                label={t("aiDecl.base.add.label")}
                placeholder={t("aiDecl.examplePrefix", { example: "Qwen/Qwen2.5-0.5B" })}
                button={t("aiDecl.base.add.button")}
                onAdd={(ref) => dispatch({ type: "addBase", ref })}
              />
              <p className="mt-1.5 text-xs text-muted-foreground">{t("aiDecl.base.add.hint")}</p>
            </CardContent>
          </Card>
        )}
        {(decl.model?.baseModels ?? []).map((b, i) => (
          <Card key={b.ref} data-base={b.ref}>
            <CardContent className="space-y-2 p-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-medium">{b.ref}</span>
                  {create ? (
                    <Badge tone="info">{t("spdx3.status.declared")}</Badge>
                  ) : (
                    <Badge tone="low">{t("spdx3.status.auto")}</Badge>
                  )}
                </div>
                {create && (
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={t("aiDecl.removeRow", { name: b.ref })}
                    onClick={() => {
                      dispatch({ type: "removeBase", index: i });
                      heading.current?.focus();
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <label className="block text-sm font-medium" htmlFor={`base-rev-${i}`}>
                {t("aiDecl.base.revision.label")}
              </label>
              <Input
                id={`base-rev-${i}`}
                aria-describedby={`base-rev-${i}-hint`}
                value={b.revision}
                placeholder={t("aiDecl.base.revision.example")}
                onChange={(e) => set({ kind: "base", index: i }, "revision", e.target.value)}
              />
              <p id={`base-rev-${i}-hint`} className="text-xs text-muted-foreground">
                {t("aiDecl.base.revision.hint")}
              </p>
              <div aria-live="polite">
                {problemAt(`model.baseModels[${i}]`, "revision") && (
                  <p className="text-xs text-risk-critical-fg">{t("aiDecl.problem.revision")}</p>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  } else if (step === "model") {
    why = "model";
    const useFields = MODEL_USE_FIELDS.filter((k) => decl.model && k in decl.model);
    body = (
      <Card>
        <CardContent className="space-y-5 p-4">
          {!authorFromScan && (
            <Field
              ns="document"
              field={index.document.createdBy}
              value={decl.document.createdBy}
              problem={problemAt("document", "createdBy")}
              showProblems={reviewed}
              onChange={(v) => set({ kind: "document" }, "createdBy", v)}
            />
          )}
          {modelMainFields(index, decl).map(modelField)}
          {decl.model && "license" in decl.model && (
            <Field
              ns="model"
              field={MODEL_LICENSE_FIELD}
              value={decl.model.license}
              problem={problemAt("model", "license")}
              showProblems={reviewed}
              onChange={(v) => set({ kind: "model" }, "license", v)}
            />
          )}
          {useFields.length > 0 && (
            <Disclosure
              defaultOpen={hasIssueIn("model", useFields)}
              summary={<span className="text-sm font-medium">{t("aiDecl.group.use")}</span>}
            >
              <div className="mt-3 space-y-5">{useFields.map(modelField)}</div>
            </Disclosure>
          )}
        </CardContent>
      </Card>
    );
  } else if (step === "data") {
    why = "data";
    const trainFields = TRAINING_FIELDS.filter((k) => decl.model && k in decl.model);
    body = (
      <div className="space-y-3">
        {decl.datasets.map((d, i) => {
          const where = `datasets[${i}]`;
          const local = d.local !== undefined;
          const keys = Object.keys(d).filter((k) => index.dataset_DatasetPackage[k] && k !== "name");
          const main = keys.filter((k) => !DATASET_MORE_FIELDS.includes(k));
          const more = keys.filter((k) => DATASET_MORE_FIELDS.includes(k));
          const field = (k: string) => (
            <Field
              key={k}
              ns="dataset"
              field={index.dataset_DatasetPackage[k]}
              value={d[k] as Value | undefined}
              problem={problemAt(where, k)}
              showProblems={reviewed}
              onChange={(v) => set({ kind: "dataset", index: i }, k, v)}
            />
          );
          const supplier = autoOf(d.ref, "suppliedBy");
          const download = autoOf(d.ref, "downloadLocation");
          return (
            <Card key={d.ref ?? `local-${i}`} data-dataset={d.ref ?? "local"}>
              <CardContent className="space-y-4 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    {local ? (
                      <span className="text-sm font-semibold">{t("aiDecl.localTitle")}</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-semibold">{d.ref?.replace(/^huggingface:/, "")}</span>
                        {create ? (
                          <Badge tone="info">{t("aiDecl.readAtScan")}</Badge>
                        ) : (
                          <Badge tone="low">{t("spdx3.status.auto")}</Badge>
                        )}
                      </div>
                    )}
                    {(supplier || download) && (
                      <p className="mt-1 break-all text-xs text-muted-foreground">
                        {[supplier && t("aiDecl.autoSupplier", { value: supplier }), download].filter(Boolean).join(" · ")}
                      </p>
                    )}
                  </div>
                  {(local || create) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={t("aiDecl.removeRow", {
                        name: local ? (d.name as string) || t("aiDecl.localTitle") : d.ref?.replace(/^huggingface:/, ""),
                      })}
                      onClick={() => {
                        dispatch({ type: local ? "removeLocal" : "removeHub", index: i });
                        // The button is gone; the question heading keeps the keyboard in the step.
                        heading.current?.focus();
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                      {t("aiDecl.removeLocal")}
                    </Button>
                  )}
                </div>
                {"role" in d && (
                  <div className="space-y-1.5">
                    <span id={`role-${i}`} className="text-sm font-medium">
                      {t("aiDecl.role.label")}
                    </span>
                    <Choices
                      options={[...ROLES]}
                      selected={d.role ? [d.role] : []}
                      labelledBy={`role-${i}`}
                      describedBy={`role-${i}-hint`}
                      labelOf={(o) => t(`aiDecl.role.${o}`)}
                      onPick={(o) => set({ kind: "dataset", index: i }, "role", d.role === o ? "" : o)}
                    />
                    <p id={`role-${i}-hint`} className="text-xs text-muted-foreground">
                      {t("aiDecl.role.hint")}
                    </p>
                  </div>
                )}
                {local && (
                  <div className="space-y-1.5">
                    <label htmlFor={`local-name-${i}`} className="flex items-center gap-2 text-sm font-medium">
                      {t("aiDecl.dataset.name.label")}
                      <Badge variant="muted">{t("g7.required")}</Badge>
                    </label>
                    <Input
                      id={`local-name-${i}`}
                      aria-required
                      value={(d.name as string | undefined) ?? ""}
                      placeholder={t("aiDecl.examplePrefix", { example: t("aiDecl.dataset.name.example") })}
                      onChange={(e) => set({ kind: "dataset", index: i }, "name", e.target.value)}
                    />
                  </div>
                )}
                {main.map(field)}
                <SourcesEditor
                  name={d.ref ?? `local-${i}`}
                  onRecord={
                    check?.relationships
                      .filter((r) => r.type === "descendantOf" && r.fromLabel && r.fromLabel === d.ref?.replace(/^huggingface:/, ""))
                      .map((r) => r.toLabel ?? "")
                      .filter(Boolean) ?? []
                  }
                  sources={d.sources ?? []}
                  problems={all.filter((x) => x.where === where && x.field === "sources").map((x) => x.problem)}
                  allowHub={!local}
                  showProblems={reviewed}
                  onChange={(v) => set({ kind: "dataset", index: i }, "sources", v as unknown as Value)}
                />
                {more.length > 0 && (
                  <Disclosure
                    defaultOpen={hasIssueIn(where, more)}
                    summary={<span className="text-sm font-medium">{t("aiDecl.group.moreData")}</span>}
                  >
                    <div className="mt-3 space-y-5">{more.map(field)}</div>
                  </Disclosure>
                )}
                {problemAt(where, "local") && (
                  <p className="text-xs text-risk-critical-fg">{t("aiDecl.problem.localIncomplete")}</p>
                )}
              </CardContent>
            </Card>
          );
        })}
        {create && (
          <Card>
            <CardContent className="p-4">
              <AddById
                label={t("aiDecl.hub.add.label")}
                placeholder={t("aiDecl.examplePrefix", { example: "HuggingFaceH4/ultrachat_200k" })}
                button={t("aiDecl.hub.add.button")}
                onAdd={(id) => dispatch({ type: "addHub", index, id })}
              />
            </CardContent>
          </Card>
        )}
        {decl.model && (
          <Button variant="outline" size="sm" onClick={() => dispatch({ type: "addLocal", index })}>
            <Plus className="h-3.5 w-3.5" />
            {t("aiDecl.addLocal")}
          </Button>
        )}
        {trainFields.length > 0 && (
          <Card>
            <CardContent className="p-4">
              <Disclosure
                defaultOpen={hasIssueIn("model", trainFields)}
                summary={<span className="text-sm font-medium">{t("aiDecl.group.training")}</span>}
              >
                <div className="mt-3 space-y-5">{trainFields.map(modelField)}</div>
              </Disclosure>
            </CardContent>
          </Card>
        )}
      </div>
    );
  } else if (step === "legal") {
    why = "legal";
    body = (
      <Card>
        <CardContent className="space-y-5 p-4">{judgmentFields(index, decl).map(modelField)}</CardContent>
      </Card>
    );
  } else {
    why = "preview";
    const open = all;
    body = (
      <div className="space-y-3">
        <Card>
          <CardContent className="space-y-2 p-4 text-sm">
            {open.length === 0 ? (
              <p className="flex items-center gap-2 text-success">
                <Check className="h-4 w-4" />
                {t("aiDecl.preview.complete")}
              </p>
            ) : (
              <>
                <p>{t("aiDecl.preview.open", { count: open.length })}</p>
                <ul className="space-y-1">
                  {steps
                    .filter((s) => s !== "preview" && open.some((i) => stepOf(i) === s))
                    .map((s) => (
                      <li key={s}>
                        <button
                          type="button"
                          className="text-brand-strong underline-offset-2 hover:underline"
                          onClick={() => go(s)}
                        >
                          {t(`aiDecl.step.${s}`)}: {t("aiDecl.preview.openInStep", { count: open.filter((i) => stepOf(i) === s).length })}
                        </button>
                      </li>
                    ))}
                </ul>
                <p className="text-xs text-muted-foreground">
                  {blockers.length ? t("aiDecl.preview.blocked") : t("aiDecl.preview.draftOk")}
                </p>
              </>
            )}
          </CardContent>
        </Card>
        <Disclosure summary={<span className="text-sm font-medium">{t("aiDecl.preview.file")}</span>}>
          <pre className="mt-2 max-h-80 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
            {JSON.stringify(toFile(decl, create), null, 2)}
          </pre>
        </Disclosure>
        {failure && (
          <div
            role="alert"
            className="space-y-1 rounded-md border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical-fg"
          >
            <div className="font-medium">
              {failure.status === 422
                ? t("aiDecl.saveRefused")
                : failure.status === 409
                  ? t("aiDecl.saveBusy")
                  : t("aiDecl.saveFailed")}
            </div>
            {failure.reasons && (
              <ul className="list-disc space-y-0.5 pl-5 font-mono">
                {failure.reasons.slice(0, 10).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[12rem_minmax(0,1fr)_16rem]" data-testid="ai-declaration">
      <nav aria-label={t("aiDecl.stepsLabel")} className="space-y-4">
        <div className="truncate text-xs text-muted-foreground">{title}</div>
        <ol className="space-y-2">
          {steps.map((s, i) => {
            const done = i < stepIndex;
            return (
              <li key={s}>
                <button
                  type="button"
                  onClick={() => go(s)}
                  aria-current={s === step ? "step" : undefined}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-md px-1 py-1 text-left text-sm",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    s === step ? "font-semibold" : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <span
                    className={cn(
                      "flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[0.7rem]",
                      done && "border-foreground bg-foreground text-background",
                    )}
                  >
                    {done ? <Check className="h-3 w-3" /> : i + 1}
                  </span>
                  {t(`aiDecl.step.${s}`)}
                </button>
              </li>
            );
          })}
        </ol>
        <div className="space-y-1.5">
          <div className="text-xs text-muted-foreground" aria-live="polite">
            {t("aiDecl.remaining", { count: remaining })}
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted" aria-hidden>
            <div
              className="h-full bg-foreground"
              style={{ width: `${totalRequired ? ((totalRequired - remaining) / totalRequired) * 100 : 100}%` }}
            />
          </div>
        </div>
      </nav>

      <div className="min-w-0 space-y-4">
        <div>
          <h2 ref={heading} tabIndex={-1} className="text-xl font-semibold focus:outline-none">
            {t(`aiDecl.question.${step}`)}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {t(create ? `aiDecl.questionHintCreate.${step}` : `aiDecl.questionHint.${step}`)}
          </p>
        </div>
        {body}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
          <Button variant="ghost" onClick={onCancel}>
            {t("aiDecl.cancel")}
          </Button>
          <div className="flex gap-2">
            {stepIndex > 0 && (
              <Button variant="outline" onClick={() => go(steps[stepIndex - 1])}>
                {t("aiDecl.prev")}
              </Button>
            )}
            {step === "preview" ? (
              <Button onClick={save} disabled={saving || blockers.length > 0}>
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                {create ? t("aiDecl.startScan") : t("aiDecl.save")}
              </Button>
            ) : (
              <Button onClick={() => go(steps[stepIndex + 1])}>
                {t("aiDecl.next", { step: t(`aiDecl.step.${steps[stepIndex + 1]}`) })}
              </Button>
            )}
          </div>
        </div>
      </div>

      <aside className="space-y-3">
        {decl.model?.baseModels?.length ? (
          <Card>
            <CardContent className="space-y-1.5 p-4 text-sm">
              <div className="font-semibold">{t("aiDecl.side.baseTitle")}</div>
              {decl.model.baseModels.map((b) => (
                <div key={b.ref} className="font-mono text-xs">
                  {b.ref}
                </div>
              ))}
              <p className="text-xs text-muted-foreground">{t("aiDecl.side.baseNote")}</p>
            </CardContent>
          </Card>
        ) : null}
        <Card>
          <CardContent className="space-y-1.5 p-4 text-sm">
            <div className="font-semibold">{t("aiDecl.whyTitle")}</div>
            <p className="text-xs text-muted-foreground">{t(`aiDecl.why.${why}`)}</p>
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
