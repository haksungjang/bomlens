// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The publisher's declaration for a scan's SPDX 3.0.1 AI document, as the
 * screens edit it.
 *
 * The converter (`docker/lib/convert-to-spdx3-ai.py`) owns the rules: the field
 * mapping (`spdx3-ai-map.json`), the empty declaration it writes for a scan
 * (only the fields the scan left open), and the check of a saved declaration.
 * This module reads those, keeps the answers, and repeats the converter's
 * value checks so a person sees a mistake beside the field rather than as a
 * refusal after saving. The server's check still decides.
 */
import type { Spdx3Counts } from "./api";

// ---- the mapping --------------------------------------------------------------

export interface MapField {
  id: string;
  type: string;
  min: number;
  max: number | "*";
  /** The field's vocabulary has its own "unknown" value (PresenceType, DatasetType). */
  noAssertion: boolean;
  enum?: string[];
  source: { kind: string };
  declarable?: boolean;
  judgment?: boolean;
}

export type ElementType = "document" | "ai_AIPackage" | "dataset_DatasetPackage";

/** Field definitions by element type and field id. */
export type FieldIndex = Record<ElementType, Record<string, MapField>>;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read the mapping the server serves; null when it is not the expected shape. */
export function parseMap(raw: unknown): FieldIndex | null {
  if (!isObj(raw) || !isObj(raw.elements)) return null;
  const out = {} as FieldIndex;
  for (const et of ["document", "ai_AIPackage", "dataset_DatasetPackage"] as const) {
    const el = raw.elements[et];
    if (!isObj(el) || !Array.isArray(el.fields)) return null;
    const fields: Record<string, MapField> = {};
    for (const f of el.fields) {
      if (!isObj(f) || typeof f.id !== "string" || typeof f.type !== "string") continue;
      fields[f.id] = {
        id: f.id,
        type: f.type,
        min: typeof f.min === "number" ? f.min : 0,
        max: f.max === "*" ? "*" : typeof f.max === "number" ? f.max : 1,
        noAssertion: f.noAssertion === true,
        enum: Array.isArray(f.enum) ? f.enum.filter((x): x is string => typeof x === "string") : undefined,
        source: isObj(f.source) && typeof f.source.kind === "string" ? { kind: f.source.kind } : { kind: "user" },
        declarable: f.declarable === true,
        judgment: f.judgment === true,
      };
    }
    out[et] = fields;
  }
  return out;
}

// ---- the check ------------------------------------------------------------------

export type FieldStatus = keyof Spdx3Counts;

export interface CheckField {
  id: string;
  status: FieldStatus;
  /** The written value, shortened; only on a filled field. */
  display?: string;
  /** "cdx:<what>" or "rule:<name>" for a value the scan filled. */
  source?: string;
  meaning?: string;
}

export interface CheckElement {
  type: string;
  label: string;
  /** "document", "model", "huggingface:<id>" or "local:<slug>"; absent for an
   *  element a declaration cannot address. */
  declarationKey?: string;
  fields: CheckField[];
}

export interface CheckRelationship {
  type: string;
  status: string | null;
  note?: string;
  /** The names of the elements it points to, where the check describes them. */
  toLabel?: string;
}

export interface Spdx3Check {
  draft: boolean;
  counts: Partial<Spdx3Counts>;
  elements: CheckElement[];
  relationships: CheckRelationship[];
  messages: { level: string; text: string }[];
}

const STATUSES: FieldStatus[] = [
  "auto",
  "declared",
  "optional",
  "judgment",
  "missingRequired",
  "noAssertion",
  "omitted",
  "review",
];

/** Read `_spdx3-check.json`; null when it is not the expected shape. */
export function parseCheck(raw: unknown): Spdx3Check | null {
  if (!isObj(raw) || !Array.isArray(raw.elements) || !isObj(raw.counts)) return null;
  const elements: CheckElement[] = [];
  const labels = new Map<string, string>();
  for (const e of raw.elements) {
    if (isObj(e) && typeof e.spdxId === "string" && typeof e.label === "string") labels.set(e.spdxId, e.label);
  }
  for (const e of raw.elements) {
    if (!isObj(e) || !Array.isArray(e.fields)) continue;
    const fields: CheckField[] = [];
    for (const f of e.fields) {
      if (!isObj(f) || typeof f.id !== "string") continue;
      const status = STATUSES.includes(f.status as FieldStatus) ? (f.status as FieldStatus) : "omitted";
      fields.push({
        id: f.id,
        status,
        display: typeof f.display === "string" ? f.display : undefined,
        source: typeof f.source === "string" ? f.source : undefined,
        meaning: typeof f.meaning === "string" ? f.meaning : undefined,
      });
    }
    elements.push({
      type: typeof e.type === "string" ? e.type : "",
      label: typeof e.label === "string" ? e.label : "",
      declarationKey: typeof e.declarationKey === "string" ? e.declarationKey : undefined,
      fields,
    });
  }
  const counts: Partial<Spdx3Counts> = {};
  for (const s of STATUSES) {
    const v = raw.counts[s];
    if (typeof v === "number" && Number.isFinite(v)) counts[s] = v;
  }
  return {
    draft: raw.draft === true,
    counts,
    elements,
    relationships: Array.isArray(raw.relationships)
      ? raw.relationships.filter(isObj).map((r) => {
          const to = (Array.isArray(r.to) ? r.to : [r.to])
            .map((x) => (typeof x === "string" ? labels.get(x) : undefined))
            .filter((x): x is string => Boolean(x));
          return {
            type: typeof r.type === "string" ? r.type : "",
            status: typeof r.status === "string" ? r.status : null,
            note: typeof r.note === "string" ? r.note : undefined,
            toLabel: to.length ? to.join(", ") : undefined,
          };
        })
      : [],
    messages: Array.isArray(raw.messages)
      ? raw.messages
          .filter(isObj)
          .filter((m) => typeof m.text === "string")
          .map((m) => ({ level: typeof m.level === "string" ? m.level : "info", text: m.text as string }))
      : [],
  };
}

/** The four groups the status band draws, in order. "Optional" also holds the
 *  relationships and sources to check, and the vocabulary's own "unknown". */
export interface BandSegment {
  key: "filled" | "optional" | "judgment" | "missingRequired";
  count: number;
}

export function bandSegments(counts: Partial<Spdx3Counts>): BandSegment[] {
  const n = (k: FieldStatus) => counts[k] ?? 0;
  return [
    { key: "filled", count: n("auto") + n("declared") },
    { key: "optional", count: n("optional") + n("noAssertion") + n("review") },
    { key: "judgment", count: n("judgment") },
    { key: "missingRequired", count: n("missingRequired") },
  ];
}

// ---- the declaration --------------------------------------------------------------

export const DECLARATION_SCHEMA = "bomlens-ai-declaration/1";
/** "Agent" is what the converter writes for an agent of no stated kind. */
export const AGENT_TYPES = ["Organization", "Person", "Agent"] as const;
export const ROLES = ["trainedOn", "testedOn", "other"] as const;
export const URI_SCHEMES = ["http", "https", "s3", "gs", "ftp", "sftp", "git", "git+https", "git+ssh", "hf"];
export const MAX_TEXT = 4000;
const REVISION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const DATE_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

export interface Agent {
  type?: string;
  name: string;
}
export interface DictEntry {
  key: string;
  value: string;
}
export type Value = string | string[] | Agent | Agent[] | DictEntry[] | null;

export interface DeclDataset {
  ref?: string;
  local?: string;
  name?: string;
  role?: string;
  [field: string]: Value | undefined;
}

export interface BaseModelEntry {
  ref: string;
  revision: string;
}

/** The model's answers by field id, plus the base models' revisions. */
export interface ModelAnswers {
  [field: string]: Value | BaseModelEntry[] | undefined;
  baseModels?: BaseModelEntry[];
}

export interface Declaration {
  schema: string;
  document: { createdBy?: Agent[] };
  /** Absent when the scan's root is a dataset. */
  model?: ModelAnswers;
  datasets: DeclDataset[];
  relationships: unknown[];
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function asDeclaration(raw: unknown): Declaration | null {
  if (!isObj(raw)) return null;
  const doc = isObj(raw.document) ? raw.document : {};
  return {
    schema: DECLARATION_SCHEMA,
    document: Array.isArray(doc.createdBy) ? { createdBy: clone(doc.createdBy) as Agent[] } : {},
    model: isObj(raw.model) ? (clone(raw.model) as Declaration["model"]) : undefined,
    datasets: Array.isArray(raw.datasets) ? (clone(raw.datasets.filter(isObj)) as DeclDataset[]) : [],
    relationships: [],
  };
}

/**
 * Where a fill starts: the empty declaration the server wrote for this scan,
 * with the answers of a declaration saved earlier laid over it. A saved answer
 * for a dataset or base model the scan no longer has is dropped (the server
 * would refuse it); datasets the hub does not hold are kept as they were.
 */
export function startDeclaration(template: unknown, saved?: unknown): Declaration | null {
  const out = asDeclaration(template);
  if (!out) return null;
  const prev = saved === undefined || saved === null ? null : asDeclaration(saved);
  if (!prev) return out;
  if (prev.document.createdBy?.length) out.document.createdBy = prev.document.createdBy;
  if (out.model && prev.model) {
    const bases = out.model.baseModels ?? [];
    for (const [k, v] of Object.entries(prev.model)) {
      if (k !== "baseModels") out.model[k] = v as Value;
    }
    const revs = new Map((prev.model.baseModels ?? []).map((b) => [b.ref, b.revision ?? ""]));
    out.model.baseModels = bases.map((b) => ({ ref: b.ref, revision: revs.get(b.ref) ?? b.revision ?? "" }));
  }
  const byRef = new Map(prev.datasets.filter((d) => d.ref).map((d) => [d.ref, d]));
  out.datasets = out.datasets.map((d) => {
    const p = d.ref ? byRef.get(d.ref) : undefined;
    if (!p) return d;
    const merged: DeclDataset = { ...d };
    for (const [k, v] of Object.entries(p)) {
      // A role only where the template offers one (a dataset the card names).
      if (k === "role" && !("role" in d)) continue;
      if (k !== "ref" && k !== "name") merged[k] = v;
    }
    return merged;
  });
  if (out.model) out.datasets.push(...prev.datasets.filter((d) => d.local));
  return out;
}

/** No answer: nothing typed, an agent with no name, a setting row with neither
 *  a name nor a value. Such rows are dropped from the saved file. */
export function isEmpty(v: unknown): boolean {
  return (
    v === undefined ||
    v === null ||
    (typeof v === "string" && v.trim() === "") ||
    (Array.isArray(v) && v.length === 0) ||
    (isObj(v) && "name" in v && typeof v.name === "string" && v.name.trim() === "") ||
    (isObj(v) && "key" in v && !String(v.key ?? "").trim() && !String(v.value ?? "").trim())
  );
}

/** Text length as the converter counts it (code points, not UTF-16 units). */
function textLength(s: string): number {
  return [...s].length;
}

/** A dataset the hub does not hold that was added and left with nothing in
 *  it: neither counted nor saved. */
export function isBlankLocal(d: DeclDataset): boolean {
  return d.local !== undefined && Object.entries(d).every(([k, v]) => k === "local" || isEmpty(v));
}

/** A new, empty dataset the hub does not hold. */
export function emptyLocalDataset(index: FieldIndex): DeclDataset {
  const d: DeclDataset = { local: "", name: "", role: "" };
  for (const f of Object.values(index.dataset_DatasetPackage)) {
    if (f.source.kind === "user" || f.declarable) d[f.id] = f.max === "*" ? [] : f.type === "Agent" ? null : "";
  }
  return d;
}

/** A slug for a dataset the hub does not hold, made from its name. Names with
 *  no Latin letters or digits fall back to a numbered one. */
export function slugFor(name: string, taken: string[], n: number): string {
  let base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "")
    .slice(0, 56);
  if (!base) base = `dataset-${n}`;
  let slug = base;
  for (let i = 2; taken.includes(slug); i++) slug = `${base}-${i}`;
  return slug;
}

// ---- dates ------------------------------------------------------------------------

/** "2025-04-15" as the declaration writes it ("2025-04-15T00:00:00Z"). */
export function dateToDeclared(day: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? `${day}T00:00:00Z` : day;
}

/** The day part a date input shows. */
export function declaredToDate(v: unknown): string {
  return typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : "";
}

function realDateTime(v: string): boolean {
  const m = DATE_TIME_RE.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return (
    t.getUTCFullYear() === y &&
    t.getUTCMonth() === mo - 1 &&
    t.getUTCDate() === d &&
    h < 24 &&
    mi < 60 &&
    s < 60
  );
}

// ---- checking ----------------------------------------------------------------------

/** A problem with one value: a stable code for the screen's wording. */
export type Problem =
  | "date"
  | "uri"
  | "uriScheme"
  | "tooLong"
  | "agentName"
  | "duplicateKey"
  | "emptyKey"
  | "revision"
  | "noAssertionMixed"
  /** A dataset the hub does not hold, partly filled but missing its name or
   *  address: the server would refuse the whole declaration. */
  | "localIncomplete";

/** Check one value against its field, as the converter does. Null when fine
 *  (an empty value is fine here; whether it is required is counted apart). */
export function checkValue(field: MapField, v: unknown): Problem | null {
  if (isEmpty(v)) return null;
  switch (field.type) {
    case "DateTime":
      return typeof v === "string" && realDateTime(v) ? null : "date";
    case "anyURI": {
      if (typeof v !== "string" || /\s/.test(v)) return "uri";
      const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/[^/?#]+/.exec(v);
      if (!m) return "uri";
      // An unclosed IPv6 bracket is not an address (the converter's parser rejects it).
      const host = m[0].slice(m[1].length + 3);
      if (host.includes("[") !== host.includes("]")) return "uri";
      if (!URI_SCHEMES.includes(m[1].toLowerCase())) return "uriScheme";
      return textLength(v) > MAX_TEXT ? "tooLong" : null;
    }
    case "Agent": {
      const list = (Array.isArray(v) ? v : [v]) as Agent[];
      for (const a of list) {
        if (!isObj(a) || typeof a.name !== "string" || !a.name.trim()) return "agentName";
        if (textLength(a.name) > MAX_TEXT) return "tooLong";
      }
      return null;
    }
    case "DictionaryEntry": {
      const list = (v as DictEntry[]).filter((e) => !isEmpty(e));
      const keys = list.map((e) => (e.key ?? "").trim());
      if (keys.some((k) => !k)) return "emptyKey";
      if (new Set(keys).size !== keys.length) return "duplicateKey";
      return list.some((e) => textLength(e.key) > 200 || textLength(e.value ?? "") > MAX_TEXT) ? "tooLong" : null;
    }
    default:
      if (Array.isArray(v)) {
        if (field.enum && v.includes("noAssertion") && v.length > 1) return "noAssertionMixed";
        return v.some((x) => typeof x === "string" && textLength(x) > MAX_TEXT) ? "tooLong" : null;
      }
      return typeof v === "string" && textLength(v) > MAX_TEXT ? "tooLong" : null;
  }
}

/** One required field still empty, or one value with a problem. */
export interface Issue {
  /** "document", "model", "model.baseModels[0]", "datasets[2]" */
  where: string;
  field: string;
  problem: Problem | "required";
}

function required(f: MapField): boolean {
  return f.min >= 1;
}

/**
 * Every required field left empty and every value with a problem. Only fields
 * the declaration holds are counted: the server's empty declaration lists just
 * what the scan left open, so a filled-by-the-scan field never shows here.
 * `authorFromScan` is true when the scan named its author (--sbom-author), so
 * the document's author is not asked for.
 */
export function issues(index: FieldIndex, decl: Declaration, authorFromScan: boolean): Issue[] {
  const out: Issue[] = [];
  const visit = (where: string, fields: Record<string, MapField>, values: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(values)) {
      const f = fields[k];
      if (!f) continue;
      if (isEmpty(v)) {
        if (required(f)) out.push({ where, field: k, problem: "required" });
        continue;
      }
      const p = checkValue(f, v);
      if (p) out.push({ where, field: k, problem: p });
    }
  };
  if (!authorFromScan) {
    if (isEmpty(decl.document.createdBy)) out.push({ where: "document", field: "createdBy", problem: "required" });
    else {
      const p = checkValue(index.document.createdBy, decl.document.createdBy);
      if (p) out.push({ where: "document", field: "createdBy", problem: p });
    }
  }
  if (decl.model) {
    visit("model", index.ai_AIPackage, decl.model);
    (decl.model.baseModels ?? []).forEach((b, i) => {
      if (!isEmpty(b.revision) && !REVISION_RE.test(b.revision.trim()))
        out.push({ where: `model.baseModels[${i}]`, field: "revision", problem: "revision" });
    });
  }
  decl.datasets.forEach((d, i) => {
    if (isBlankLocal(d)) return;
    const where = `datasets[${i}]`;
    visit(where, index.dataset_DatasetPackage, d);
    if (d.local !== undefined && (isEmpty(d.name) || isEmpty(d.downloadLocation)))
      out.push({ where, field: "local", problem: "localIncomplete" });
  });
  return out;
}

export function remainingRequired(list: Issue[]): number {
  return list.filter((i) => i.problem === "required").length;
}

/** What the server would refuse: a value with a problem, or a dataset the hub
 *  does not hold without its name or address. A required field left empty is
 *  not one of them; the document then stays a draft. */
export function saveBlockers(list: Issue[]): Issue[] {
  return list.filter((i) => i.problem !== "required");
}

// ---- the file ------------------------------------------------------------------------

function pruned(v: Value | undefined): Value | undefined {
  if (v === undefined || isEmpty(v)) return undefined;
  if (Array.isArray(v)) {
    const kept = (v as unknown[]).filter((x) => !isEmpty(x));
    return kept.length ? (kept as Value) : undefined;
  }
  if (typeof v === "string") return v.trim();
  return v;
}

/**
 * The declaration as it is saved: empty answers left out, so the file holds
 * only what the publisher said. A dataset with nothing declared is left out,
 * and so is one the hub does not hold that was added and never filled.
 */
export function toFile(decl: Declaration): Declaration {
  const out: Declaration = { schema: DECLARATION_SCHEMA, document: {}, datasets: [], relationships: [] };
  const agents = pruned(decl.document.createdBy as Value);
  if (agents) out.document.createdBy = agents as Agent[];
  if (decl.model) {
    const m: NonNullable<Declaration["model"]> = {};
    for (const [k, v] of Object.entries(decl.model)) {
      if (k === "baseModels") continue;
      const p = pruned(v as Value);
      if (p !== undefined) m[k] = p;
    }
    const bases = (decl.model.baseModels ?? []).filter((b) => !isEmpty(b.revision));
    if (bases.length) m.baseModels = bases.map((b) => ({ ref: b.ref, revision: b.revision.trim() }));
    out.model = m;
  }
  for (const d of decl.datasets) {
    const e: DeclDataset = {};
    for (const [k, v] of Object.entries(d)) {
      if (k === "ref" || k === "local") continue;
      const p = pruned(v as Value);
      if (p !== undefined) e[k] = p;
    }
    if (d.local !== undefined) {
      if (!isBlankLocal(d)) out.datasets.push({ local: d.local, ...e });
    } else if (Object.keys(e).length) out.datasets.push({ ref: d.ref, ...e });
  }
  return out;
}

// ---- where each question goes --------------------------------------------------------

export type StepId = "base" | "model" | "data" | "legal" | "preview";

/** Model fields asked under "Use and scope (optional)", folded by default. */
export const MODEL_USE_FIELDS = ["domain", "informationAboutApplication", "standardCompliance", "modelExplainability"];
/** Model fields asked under "How it was trained (optional)", beside the data. */
export const TRAINING_FIELDS = ["informationAboutTraining", "hyperparameter", "modelDataPreprocessing"];
/** Dataset fields folded under "More about this data (optional)". */
export const DATASET_MORE_FIELDS = [
  "intendedUse",
  "knownBias",
  "confidentialityLevel",
  "dataCollectionProcess",
  "anonymizationMethodUsed",
  "dataPreprocessing",
  "datasetNoise",
  "datasetUpdateMechanism",
];
/** Text fields that take a sentence or more. */
export const LONG_TEXT = new Set([
  "informationAboutTraining",
  "informationAboutApplication",
  "dataCollectionProcess",
  "intendedUse",
  "datasetNoise",
  "datasetUpdateMechanism",
]);

/** The model step's main questions: everything open on the model that is not a
 *  judgment, not folded into "use and scope", and not about training. */
export function modelMainFields(index: FieldIndex, decl: Declaration): string[] {
  if (!decl.model) return [];
  return Object.keys(decl.model).filter((k) => {
    const f = index.ai_AIPackage[k];
    return f && !f.judgment && !MODEL_USE_FIELDS.includes(k) && !TRAINING_FIELDS.includes(k);
  });
}

export function judgmentFields(index: FieldIndex, decl: Declaration): string[] {
  if (!decl.model) return [];
  return Object.keys(decl.model).filter((k) => index.ai_AIPackage[k]?.judgment);
}

/** The steps this declaration needs, in order. A dataset scan has no model, so
 *  it asks only about the data. */
export function stepsFor(index: FieldIndex, decl: Declaration): StepId[] {
  const steps: StepId[] = [];
  if (decl.model?.baseModels?.length) steps.push("base");
  if (decl.model) steps.push("model");
  steps.push("data");
  if (judgmentFields(index, decl).length) steps.push("legal");
  steps.push("preview");
  return steps;
}

/** The step an issue belongs to, so the progress list can say which step still
 *  has something open. */
export function stepOf(issue: Issue): StepId {
  if (issue.where === "document") return "model";
  if (issue.where.startsWith("model.baseModels")) return "base";
  if (issue.where.startsWith("datasets")) return "data";
  if (TRAINING_FIELDS.includes(issue.field)) return "data";
  return issue.field === "useSensitivePersonalInformation" ||
    issue.field === "autonomyType" ||
    issue.field === "safetyRiskAssessment"
    ? "legal"
    : "model";
}
