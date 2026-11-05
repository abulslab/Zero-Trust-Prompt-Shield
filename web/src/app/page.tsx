"use client";
import Link from "next/link";
import { Badge, Button, ErrorBox, PageHeader, Panel, Spinner, Stat, Table, fmtDate, statusTone } from "@/components/ui";
import { Legend, categoryBar } from "@/components/shield";
import { fmt, useApi } from "@/lib/api";

function Bars({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <p className="py-6 text-center text-sm text-slate-500">No findings yet.</p>;
  return (
    <div className="space-y-2">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-3 text-sm">
          <span className="w-28 shrink-0 text-slate-600">{fmt.label(k)}</span>
          <div className="h-2 flex-1 rounded-full bg-slate-100">
            <div className={`h-2 rounded-full ${categoryBar[k] ?? "bg-slate-400"}`} style={{ width: `${(v / max) * 100}%` }} />
          </div>
          <span className="w-10 text-right tabular-nums text-slate-700">{v}</span>
        </div>
      ))}
    </div>
  );
}

function Daily({ days }: { days: { date: string; total: number; blocked: number; redacted: number }[] }) {
  if (!days.length) return <p className="py-6 text-center text-sm text-slate-500">No activity yet.</p>;
  const max = Math.max(1, ...days.map((d) => d.total));
  return (
    <div className="flex h-36 items-end gap-1.5" role="img" aria-label="Inspections per day">
      {days.map((d) => (
        <div key={d.date} className="flex flex-1 flex-col items-center gap-1" title={`${d.date}: ${d.total} inspections, ${d.blocked} blocked, ${d.redacted} redacted`}>
          <div className="flex w-full flex-col-reverse overflow-hidden rounded-sm" style={{ height: `${(d.total / max) * 110}px` }}>
            <div className="bg-red-500" style={{ height: `${(d.blocked / Math.max(1, d.total)) * 100}%` }} />
            <div className="bg-amber-400" style={{ height: `${(d.redacted / Math.max(1, d.total)) * 100}%` }} />
            <div className="flex-1 bg-blue-600" />
          </div>
          <span className="text-[10px] tabular-nums text-slate-400">{d.date.slice(5)}</span>
        </div>
      ))}
    </div>
  );
}

export default function Overview() {
  const stats = useApi<any>("/v1/stats", { refetch: 10000 });
  const recent = useApi<any[]>("/v1/audit?limit=8", { refetch: 10000 });
  if (stats.error) return <><PageHeader title="Overview" /><ErrorBox error={stats.error} /></>;
  if (!stats.data) return <Spinner />;
  const s = stats.data;
  const pct = (n: number) => (s.inspections ? `${Math.round((n / s.inspections) * 100)}%` : "—");

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Every prompt, document and answer that passed through the shield: what was found, what was decided, and what people said about it. Text is never stored."
        actions={<Link href="/inspect"><Button>Inspect text</Button></Link>}
      />
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Inspections" value={fmt.num(s.inspections)} hint={`${s.ai_reviews} with AI review`} />
        <Stat label="Blocked" value={fmt.num(s.by_action.block ?? 0)} hint={`${pct(s.by_action.block ?? 0)} of all`} />
        <Stat label="Redacted" value={fmt.num(s.by_action.redact ?? 0)} hint={`${pct(s.by_action.redact ?? 0)} sent after redaction`} />
        <Stat label="Average risk" value={s.avg_risk} hint={`${fmt.num(s.findings)} findings · ${s.feedback?.false_positive ?? 0} dismissed`} />
      </div>
      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Panel title="Findings by category" subtitle="Last 1,000 inspections, suppressed findings excluded."><Bars data={s.by_category} /></Panel>
        <Panel title="Activity" subtitle="Inspections per day: blocked (red), redacted (amber), allowed or warned (blue)."><Daily days={s.daily} /></Panel>
      </div>
      <Panel title="Recent inspections" flush actions={<Link className="text-xs font-medium text-blue-700 hover:underline" href="/audit">Audit log</Link>}>
        <Table
          head={["Inspection", "Source", "Direction", "Decision", "Risk", "Findings", "When"]}
          empty={<>Nothing yet. <Link className="font-medium text-blue-700 hover:underline" href="/inspect">Inspect some text</Link>.</>}
          rows={(recent.data ?? []).map((r) => [
            <Link key="i" href={`/audit/${r.id}`} className="font-mono text-xs font-medium text-blue-700 hover:underline">{r.id}</Link>,
            <span key="s">{r.source}</span>,
            <span key="d">{r.direction}</span>,
            <Badge key="a" tone={statusTone(r.action)}>{r.action}</Badge>,
            <span key="r" className="tabular-nums">{r.risk_score}</span>,
            <Legend key="c" counts={r.counts} />,
            <span key="w" className="whitespace-nowrap text-xs text-slate-500">{fmtDate(r.created_at)}</span>,
          ])}
        />
      </Panel>
    </>
  );
}
