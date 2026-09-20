// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// helpmenu.mjs 단위 테스트(electron 비의존). 실제 메뉴 표시는 데스크톱 앱에서 확인한다.
import assert from "node:assert/strict";
import { test } from "node:test";
import { addReportItem, ISSUE_FORM_URL } from "../lib/helpmenu.mjs";

class FakeItem {
  constructor(opts) {
    Object.assign(this, opts);
  }
}
const opts = { label: "Report a problem...", helpLabel: "Help", onClick: () => {} };

test("the report item is appended to an existing Help submenu", () => {
  const appended = [];
  const menu = {
    items: [{ role: "fileMenu" }, { role: "help", submenu: { append: (i) => appended.push(i) } }],
    append: () => assert.fail("must not create a second Help menu"),
  };
  assert.equal(addReportItem(menu, FakeItem, opts), true);
  assert.equal(appended.length, 1);
  assert.equal(appended[0].label, "Report a problem...");
  assert.equal(appended[0].click, opts.onClick);
});

test("a Help menu is created when the default menu has none", () => {
  const top = [];
  const menu = { items: [{ role: "fileMenu" }], append: (i) => top.push(i) };
  assert.equal(addReportItem(menu, FakeItem, opts), true);
  assert.equal(top.length, 1);
  assert.equal(top[0].label, "Help");
  assert.equal(top[0].role, "help");
  assert.equal(top[0].submenu[0].label, "Report a problem...");
});

test("no menu, nothing to do", () => {
  assert.equal(addReportItem(null, FakeItem, opts), false);
});

test("the issue form is the YAML bug-report template", () => {
  assert.equal(ISSUE_FORM_URL, "https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml");
});
