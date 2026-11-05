"use client";
import { Badge, Button, ErrorBox, PageHeader, Panel, Spinner, Table, fmtDate, statusTone } from "@/components/ui";
import { api, useAction, useApi } from "@/lib/api";

export default function ReviewPage() {
  const fb = useApi<any[]>("/v1/feedback");
  const del = useAction((id: string) => api(`/v1/feedback/${id}`, { method: "DELETE" }), ["/v1/feedback"]);
  const list = fb.data ?? [];
  const fp = list.filter((x) => x.verdict === "false_positive");
  const tp = list.filter((x) => x.verdict === "true_positive");
  const byRule = Object.entries(
    list.reduce<Record<string, { fp: number; tp: number }>>((acc, x) => {
      acc[x.rule_id] ??= { fp: 0, tp: 0 };
      acc[x.rule_id][x.verdict === "false_positive" ? "fp" : "tp"] += 1;
      return acc;
    }, {}),
  ).sort((a, b) => b[1].fp - a[1].fp);

  return (
    <>
      <PageHeader
        title="Review"
        subtitle="What people decided about findings. 'Dismiss' suppresses that exact value for that rule in later inspections (matched by fingerprint, so the value itself is never stored). Rules with many suppressions need tuning."
      />
      <ErrorBox error={fb.error ?? del.error} />
      {!fb.data && !fb.error ? <Spinner /> : (
        <div className="space-y-6">
          <Panel title="Rule quality" subtitle="Precision as people judged it." flush>
            <Table
              head={["Rule", "Confirmed", "Dismissed", "Judged precision"]}
              empty="No decisions yet. Mark findings as Real or Dismiss them on the Inspect page."
              rows={byRule.map(([rule, c]) => [
                <span key="r" className="font-mono text-xs">{rule}</span>,
                <span key="t" className="tabular-nums">{c.tp}</span>,
                <span key="f" className="tabular-nums">{c.fp}</span>,
                <span key="p" className="tabular-nums">{Math.round((c.tp / (c.tp + c.fp)) * 100)}%</span>,
              ])}
            />
          </Panel>
          <Panel title={`Suppressions (${fp.length})`} subtitle={`${tp.length} findings confirmed as real.`} flush>
            <Table
              head={["Rule", "Value", "Verdict", "Note", "Inspection", "When", ""]}
              empty="No suppressions."
              rows={list.map((x) => [
                <span key="r" className="font-mono text-xs">{x.rule_id}</span>,
                <code key="v" className="font-mono text-xs text-slate-600">{x.preview ?? "—"}</code>,
                <Badge key="vd" tone={statusTone(x.verdict)}>{x.verdict === "false_positive" ? "dismissed" : "real"}</Badge>,
                <span key="n" className="text-xs text-slate-600">{x.note ?? "—"}</span>,
                <span key="i" className="font-mono text-xs">{x.inspection_id ?? "—"}</span>,
                <span key="w" className="whitespace-nowrap text-xs text-slate-500">{fmtDate(x.created_at)}</span>,
                <Button key="d" size="sm" variant="ghost" onClick={() => del.mutate(x.fingerprint)}>Undo</Button>,
              ])}
            />
          </Panel>
        </div>
      )}
    </>
  );
}
