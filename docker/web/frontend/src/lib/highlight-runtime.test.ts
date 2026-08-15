// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { languageForPath } from "./highlight";
import { GRAMMARS, highlightSource } from "./highlight-runtime";

/**
 * The loading half. Its actual work — fetching a grammar chunk and running the
 * highlighter — belongs to the browser and is covered by the Playwright tests;
 * what is worth asserting here is the seam between the two halves, because a
 * mismatch there fails silently: the viewer shows plain text, which is exactly
 * what it shows when a file legitimately has no grammar.
 */
describe("grammar coverage", () => {
  it("has a loader for every language the path mapper can name", () => {
    // Sampling the mapper through its public surface rather than reading its
    // table, so a language added to the table without a loader is caught.
    const paths = [
      "a.c", "a.cc", "a.cpp", "a.cs", "a.css", "a.go", "a.gradle", "a.h",
      "a.hpp", "a.htm", "a.html", "a.java", "a.js", "a.json", "a.jsx", "a.kt",
      "a.lock", "a.md", "a.mjs", "a.php", "a.pl", "a.properties", "a.py",
      "a.rb", "a.rs", "a.sh", "a.sql", "a.swift", "a.toml", "a.ts", "a.tsx",
      "a.xml", "a.yaml", "a.yml", "Dockerfile", "Makefile", "Gemfile", "Rakefile",
    ];
    const named = new Set(paths.map(languageForPath).filter((l): l is string => l !== null));
    expect(named.size).toBeGreaterThan(20);
    for (const language of named) {
      expect(GRAMMARS, `no loader for ${language}`).toHaveProperty(language);
    }
  });

  it("names no grammar the path mapper never asks for", () => {
    // The other direction: a loader nothing can reach is a chunk built for no
    // reason, and usually means the mapper lost an extension.
    const reachable = new Set(
      [
        "a.c", "a.cpp", "a.cs", "a.css", "a.go", "a.gradle", "a.java", "a.js",
        "a.json", "a.kt", "a.md", "a.php", "a.pl", "a.properties", "a.py",
        "a.rb", "a.rs", "a.sh", "a.sql", "a.swift", "a.toml", "a.ts", "a.xml",
        "a.yaml", "Dockerfile", "Makefile",
      ].map(languageForPath),
    );
    for (const language of Object.keys(GRAMMARS)) {
      expect(reachable, `${language} is loadable but unreachable`).toContain(language);
    }
  });
});

describe("highlightSource", () => {
  it("returns null for a language it has no grammar for", async () => {
    // Takes the early exit, so nothing is imported and this stays a unit test.
    await expect(highlightSource("x = 1", "cobol")).resolves.toBeNull();
  });

  it("returns null rather than throwing on an empty language", async () => {
    await expect(highlightSource("x", "")).resolves.toBeNull();
  });
});
