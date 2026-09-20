// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Copy, ExternalLink, LifeBuoy } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { buttonVariants, Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDiagnostics } from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { copyToClipboard, ISSUE_FORM_URL } from "@/lib/diagnostics";
import { useToast } from "@/lib/toast";
import { cn } from "@/lib/utils";

/**
 * "Report a problem": the diagnostics summary of a finished scan (succeeded or
 * failed), shown in full on screen, with one button that puts exactly that text
 * on the clipboard and a link to the issue form. Nothing is sent anywhere: the
 * user reads it, copies it, and pastes it into the issue themselves.
 *
 * `scanId` is the finished scan's run id. A scan that failed before it had a run
 * folder passes none, and the server then returns the environment section only.
 */
export function ReportProblem({ scanId }: { scanId?: string | null }) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [text, setText] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "failed">("loading");
  const [copyBlocked, setCopyBlocked] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setState("loading");
    setCopyBlocked(false);
    void getDiagnostics(scanId).then((value) => {
      if (cancelled) return;
      setText(value);
      setState(value === null ? "failed" : "ready");
    });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // The demo has no server to build a summary; the help menu still links the form.
  if (IS_STATIC_DEMO) return null;

  const copy = async () => {
    if (text === null) return;
    if (await copyToClipboard(text)) {
      setCopyBlocked(false);
      toast(t("report.copied"));
    } else {
      setCopyBlocked(true);
    }
  };

  return (
    <Card className="animate-fade-in" data-testid="report-problem">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <LifeBuoy className="h-4 w-4 text-muted-foreground" aria-hidden />
          {t("report.open")}
        </CardTitle>
        <p className="text-sm text-foreground/70">{t("report.intro")}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        {state === "loading" && (
          <p className="text-sm text-foreground/70">{t("report.loading")}</p>
        )}
        {state === "failed" && (
          <p role="status" className="text-sm text-foreground/70">
            {t("report.loadFailed")}
          </p>
        )}
        {state === "ready" && text !== null && (
          <textarea
            readOnly
            value={text}
            rows={Math.min(18, text.split("\n").length + 1)}
            aria-label={t("report.label")}
            data-testid="report-text"
            className="w-full resize-y rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          />
        )}
        {copyBlocked && (
          <p role="status" className="text-sm text-foreground/70">
            {t("report.copyFailed")}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button type="button" onClick={copy} disabled={state !== "ready"}>
            <Copy className="h-4 w-4" aria-hidden />
            {t("report.copy")}
          </Button>
          <a
            href={ISSUE_FORM_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={cn(buttonVariants({ variant: "outline" }))}
          >
            <ExternalLink className="h-4 w-4" aria-hidden />
            {t("report.openIssue")}
          </a>
        </div>
      </CardContent>
    </Card>
  );
}
