// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Loading half of the syntax highlighter, kept apart from the pure half so that
 * `lib/highlight.ts` stays testable in node and free of the library.
 *
 * The grammars are the bulk of highlight.js, and most sessions never open a
 * file, so nothing here is imported until a file with a known grammar is
 * actually shown. Vite splits these dynamic imports into their own chunks; the
 * initial bundle is unchanged.
 *
 * A grammar that fails to load returns null and the viewer keeps its plain
 * text. Highlighting is a reading aid, not the content: the file must render
 * whether or not the colours arrive.
 */

/**
 * Grammar loaders, keyed by the names `languageForPath` returns.
 *
 * Exported so a test can hold the two halves against each other: a language the
 * path mapper names but this map has no loader for highlights nothing, and does
 * so silently — the viewer just shows plain text, which is also what it does
 * when there is no grammar at all.
 */
export const GRAMMARS: Record<string, () => Promise<{ default: unknown }>> = {
  bash: () => import("highlight.js/lib/languages/bash"),
  c: () => import("highlight.js/lib/languages/c"),
  cpp: () => import("highlight.js/lib/languages/cpp"),
  csharp: () => import("highlight.js/lib/languages/csharp"),
  css: () => import("highlight.js/lib/languages/css"),
  dockerfile: () => import("highlight.js/lib/languages/dockerfile"),
  go: () => import("highlight.js/lib/languages/go"),
  groovy: () => import("highlight.js/lib/languages/groovy"),
  ini: () => import("highlight.js/lib/languages/ini"),
  java: () => import("highlight.js/lib/languages/java"),
  javascript: () => import("highlight.js/lib/languages/javascript"),
  json: () => import("highlight.js/lib/languages/json"),
  kotlin: () => import("highlight.js/lib/languages/kotlin"),
  makefile: () => import("highlight.js/lib/languages/makefile"),
  markdown: () => import("highlight.js/lib/languages/markdown"),
  perl: () => import("highlight.js/lib/languages/perl"),
  php: () => import("highlight.js/lib/languages/php"),
  properties: () => import("highlight.js/lib/languages/properties"),
  python: () => import("highlight.js/lib/languages/python"),
  ruby: () => import("highlight.js/lib/languages/ruby"),
  rust: () => import("highlight.js/lib/languages/rust"),
  sql: () => import("highlight.js/lib/languages/sql"),
  swift: () => import("highlight.js/lib/languages/swift"),
  typescript: () => import("highlight.js/lib/languages/typescript"),
  xml: () => import("highlight.js/lib/languages/xml"),
  yaml: () => import("highlight.js/lib/languages/yaml"),
};

/** Grammars already registered, so a second file of the same kind is instant. */
const registered = new Set<string>();
let core: typeof import("highlight.js/lib/core").default | null = null;

/**
 * Highlight `source` as `language`, or null when that is not possible.
 *
 * Null covers every failure the same way — an unknown grammar, a chunk that did
 * not load, a highlighter that threw on malformed input — because the caller's
 * response to all of them is the same: show the text.
 */
export async function highlightSource(
  source: string,
  language: string,
): Promise<string | null> {
  const load = GRAMMARS[language];
  if (!load) return null;
  try {
    if (!core) {
      core = (await import("highlight.js/lib/core")).default;
    }
    if (!registered.has(language)) {
      const grammar = (await load()).default;
      core.registerLanguage(language, grammar as never);
      registered.add(language);
    }
    return core.highlight(source, { language, ignoreIllegals: true }).value;
  } catch {
    return null;
  }
}
