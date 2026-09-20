// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// 도움말 메뉴의 "문제 신고" 항목(순수 로직 - electron 비의존, 단위 테스트 가능).
// 웹 UI의 도움말 메뉴와 같은 이슈 양식으로 연결한다. 이 항목은 아무것도 전송하지 않고
// 양식이 열리는 브라우저 탭만 띄운다. 스캔 결과 화면의 "문제 신고" 패널은 웹 UI가 그린다.

// .github/ISSUE_TEMPLATE/bug_report.yml. 웹 UI의 ISSUE_FORM_URL(src/lib/diagnostics.ts)과 같은 값이다.
export const ISSUE_FORM_URL = "https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml";

// 기본 메뉴의 Help 하위 메뉴에 항목을 덧붙인다. 하위 메뉴가 없으면 Help 메뉴를 새로 만든다.
// 붙였으면 true. 호출한 쪽이 Menu.setApplicationMenu(menu)로 다시 적용한다.
export function addReportItem(menu, MenuItem, { label, helpLabel, onClick }) {
  if (!menu || typeof menu.append !== "function") return false;
  const item = new MenuItem({ label, click: onClick });
  const help = menu.items.find((m) => m.role === "help");
  if (help?.submenu) {
    help.submenu.append(item);
    return true;
  }
  menu.append(new MenuItem({ label: helpLabel, role: "help", submenu: [{ label, click: onClick }] }));
  return true;
}
