// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Syntax highlighting for the source viewer.
 *
 * The viewer renders one table row per line so that line numbers stay aligned
 * with wrapped text, but a highlighter marks up the file as a whole: a block
 * comment or a multi-line string opens a span on one line and closes it several
 * lines later. Splitting that markup on newlines would hand each row a fragment
 * with unbalanced tags, which the browser then repairs by guessing — usually by
 * swallowing the rest of the file into one comment.
 *
 * So the split is done properly: the open tags are tracked, closed at the end of
 * every line and reopened at the start of the next. Each row is then a complete,
 * balanced fragment on its own.
 *
 * The markup that goes in is the highlighter's, whose text is already escaped;
 * nothing here introduces text, it only moves tags. A file that fails to
 * highlight falls back to escaped plain text rather than to nothing.
 */

/** Extensions worth loading a grammar for — what these scans actually carry. */
const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  c: "c",
  cc: "cpp",
  cpp: "cpp",
  cs: "csharp",
  css: "css",
  go: "go",
  gradle: "groovy",
  h: "c",
  hpp: "cpp",
  htm: "xml",
  html: "xml",
  java: "java",
  js: "javascript",
  json: "json",
  jsx: "javascript",
  kt: "kotlin",
  lock: "yaml",
  md: "markdown",
  mjs: "javascript",
  php: "php",
  pl: "perl",
  properties: "properties",
  py: "python",
  rb: "ruby",
  rs: "rust",
  sh: "bash",
  sql: "sql",
  swift: "swift",
  toml: "ini",
  ts: "typescript",
  tsx: "typescript",
  xml: "xml",
  yaml: "yaml",
  yml: "yaml",
};

/** Filenames that carry no extension but a known grammar. */
const LANGUAGE_BY_FILENAME: Record<string, string> = {
  dockerfile: "dockerfile",
  gemfile: "ruby",
  makefile: "makefile",
  rakefile: "ruby",
};

/**
 * The grammar for a path, or null when none is worth loading.
 *
 * Null is a normal answer: a binary, a licence file or an unfamiliar extension
 * is shown as plain text rather than guessed at. Guessing costs a grammar
 * download and gets the colours wrong, which reads as a bug in the viewer.
 */
export function languageForPath(path: string): string | null {
  const name = path.split("/").pop()?.toLowerCase() ?? "";
  if (LANGUAGE_BY_FILENAME[name]) return LANGUAGE_BY_FILENAME[name];
  // A dotfile like `.bashrc` has no extension in the usual sense.
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return null;
  return LANGUAGE_BY_EXTENSION[name.slice(dot + 1)] ?? null;
}

/** Escape text for insertion as HTML — the fallback when highlighting fails. */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Split highlighter markup into one balanced fragment per line.
 *
 * Only `<span …>` and `</span>` appear in the input, which is what the
 * highlighter emits; any other tag is carried through as text rather than
 * treated as a nesting level.
 */
export function splitHighlightedLines(html: string): string[] {
  const lines: string[] = [];
  const open: string[] = [];
  let current = "";
  let i = 0;

  while (i < html.length) {
    const ch = html[i];

    if (ch === "\n") {
      // Close what is open, in reverse order, so the row stands alone.
      lines.push(current + "</span>".repeat(open.length));
      current = open.join("");
      i += 1;
      continue;
    }

    if (ch === "<") {
      const end = html.indexOf(">", i);
      if (end < 0) {
        // A truncated tag: treat the rest as text rather than dropping it.
        current += html.slice(i);
        break;
      }
      const tag = html.slice(i, end + 1);
      if (/^<span\b/.test(tag)) open.push(tag);
      else if (tag === "</span>") open.pop();
      current += tag;
      i = end + 1;
      continue;
    }

    current += ch;
    i += 1;
  }

  lines.push(current + "</span>".repeat(open.length));
  return lines;
}
