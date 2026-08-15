// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { escapeHtml, languageForPath, splitHighlightedLines } from "./highlight";

describe("languageForPath", () => {
  it("maps an extension to its grammar", () => {
    expect(languageForPath("src/main.go")).toBe("go");
    expect(languageForPath("app/models/user.rb")).toBe("ruby");
    expect(languageForPath("pom.xml")).toBe("xml");
  });

  it("recognises names that carry no extension", () => {
    expect(languageForPath("Dockerfile")).toBe("dockerfile");
    expect(languageForPath("services/api/Makefile")).toBe("makefile");
  });

  it("is case-insensitive", () => {
    expect(languageForPath("SRC/Main.JAVA")).toBe("java");
  });

  it("returns null rather than guessing", () => {
    // A binary, a licence, an unfamiliar extension, a dotfile: plain text is
    // the honest rendering, and guessing costs a grammar download to get the
    // colours wrong.
    expect(languageForPath("LICENSE")).toBeNull();
    expect(languageForPath("data.bin")).toBeNull();
    expect(languageForPath(".bashrc")).toBeNull();
    expect(languageForPath("no-extension")).toBeNull();
  });
});

describe("splitHighlightedLines", () => {
  it("returns one fragment per line", () => {
    expect(splitHighlightedLines("a\nb\nc")).toEqual(["a", "b", "c"]);
  });

  it("keeps a span that opens and closes on one line", () => {
    expect(splitHighlightedLines('<span class="hljs-keyword">if</span> x')).toEqual([
      '<span class="hljs-keyword">if</span> x',
    ]);
  });

  it("closes and reopens a span that crosses lines", () => {
    // The block-comment case: without this each row would carry unbalanced
    // markup and the browser would repair it by guessing.
    const input = '<span class="hljs-comment">/* one\ntwo\nthree */</span>';
    expect(splitHighlightedLines(input)).toEqual([
      '<span class="hljs-comment">/* one</span>',
      '<span class="hljs-comment">two</span>',
      '<span class="hljs-comment">three */</span>',
    ]);
  });

  it("handles nested spans across a line break", () => {
    const input = '<span class="a">x<span class="b">y\nz</span>w</span>';
    expect(splitHighlightedLines(input)).toEqual([
      '<span class="a">x<span class="b">y</span></span>',
      '<span class="a"><span class="b">z</span>w</span>',
    ]);
  });

  it("every fragment is balanced", () => {
    const input = '<span class="a">1\n<span class="b">2\n3</span>\n4</span>';
    for (const line of splitHighlightedLines(input)) {
      const opens = (line.match(/<span\b/g) ?? []).length;
      const closes = (line.match(/<\/span>/g) ?? []).length;
      expect(opens).toBe(closes);
    }
  });

  it("leaves escaped text alone", () => {
    // The highlighter has already escaped the source; nothing here re-escapes
    // or unescapes, which would either double the entities or undo them.
    const input = '<span class="hljs-string">"&lt;script&gt;"</span>';
    expect(splitHighlightedLines(input)).toEqual([input]);
  });

  it("carries a truncated tag through as text rather than dropping it", () => {
    expect(splitHighlightedLines("a<span")).toEqual(["a<span"]);
  });

  it("returns one empty fragment for an empty input", () => {
    expect(splitHighlightedLines("")).toEqual([""]);
  });
});

describe("escapeHtml", () => {
  it("escapes what would otherwise be markup", () => {
    expect(escapeHtml('<script>alert("x")</script>')).toBe(
      "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
    );
  });

  it("escapes the ampersand first so entities are not doubled", () => {
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });
});
