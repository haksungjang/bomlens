// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  COMPONENT_COLUMNS,
  COMPONENT_VIEW_KEY,
  parseHidden,
  readHidden,
  serializeHidden,
  toggleHidden,
  type ViewStore,
  writeHidden,
} from "./tableView";

const KNOWN = COMPONENT_COLUMNS.map((c) => c.id);

/** A stand-in for localStorage — the unit tests run under Node, which has none. */
function store(initial: Record<string, string> = {}): ViewStore & { data: Record<string, string> } {
  const data = { ...initial };
  return {
    data,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
  };
}

describe("parseHidden", () => {
  it("reads a stored list of ids", () => {
    expect(parseHidden('["scope","risk"]', KNOWN)).toEqual(["scope", "risk"]);
  });

  it("treats missing or unreadable values as nothing hidden", () => {
    expect(parseHidden(null, KNOWN)).toEqual([]);
    expect(parseHidden("", KNOWN)).toEqual([]);
    expect(parseHidden("not json", KNOWN)).toEqual([]);
    expect(parseHidden('{"scope":true}', KNOWN)).toEqual([]); // not an array
  });

  it("drops ids the table no longer has", () => {
    // A column removed in a later release would otherwise sit in storage
    // forever, and a hand-edited value could name anything at all.
    expect(parseHidden('["scope","gone","../etc/passwd"]', KNOWN)).toEqual(["scope"]);
  });

  it("drops non-strings and duplicates", () => {
    expect(parseHidden('["scope",42,null,"scope"]', KNOWN)).toEqual(["scope"]);
  });
});

describe("serializeHidden / toggleHidden", () => {
  it("round-trips through storage", () => {
    const raw = serializeHidden(["type", "license"]);
    expect(parseHidden(raw, KNOWN)).toEqual(["type", "license"]);
  });

  it("collapses duplicates on the way out", () => {
    expect(serializeHidden(["type", "type"])).toBe('["type"]');
  });

  it("toggles one column on and back off", () => {
    const once = toggleHidden([], "risk");
    expect(once).toEqual(["risk"]);
    expect(toggleHidden(once, "risk")).toEqual([]);
  });

  it("leaves the other columns alone while toggling", () => {
    expect(toggleHidden(["scope", "risk"], "scope")).toEqual(["risk"]);
  });
});

describe("readHidden / writeHidden", () => {
  it("persists a choice and reads it back", () => {
    const s = store();
    writeHidden(COMPONENT_VIEW_KEY, ["scope"], s);
    expect(readHidden(COMPONENT_VIEW_KEY, KNOWN, s)).toEqual(["scope"]);
  });

  it("reads nothing when the table was never configured", () => {
    expect(readHidden(COMPONENT_VIEW_KEY, KNOWN, store())).toEqual([]);
  });

  it("keeps working when storage is unavailable", () => {
    // Private browsing and blocked third-party storage both surface this way.
    expect(readHidden(COMPONENT_VIEW_KEY, KNOWN, null)).toEqual([]);
    expect(() => writeHidden(COMPONENT_VIEW_KEY, ["scope"], null)).not.toThrow();
  });

  it("survives a storage that throws on access", () => {
    const hostile: ViewStore = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(readHidden(COMPONENT_VIEW_KEY, KNOWN, hostile)).toEqual([]);
    expect(() => writeHidden(COMPONENT_VIEW_KEY, ["scope"], hostile)).not.toThrow();
  });
});

describe("COMPONENT_COLUMNS", () => {
  it("has unique ids and a label key for each", () => {
    expect(new Set(KNOWN).size).toBe(COMPONENT_COLUMNS.length);
    expect(COMPONENT_COLUMNS.every((c) => c.labelKey.startsWith("result."))).toBe(true);
  });

  it("does not offer to hide the name column — a row needs its identity", () => {
    expect(KNOWN).not.toContain("name");
  });
});
