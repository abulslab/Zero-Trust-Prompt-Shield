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
    <div className="space-y-2.5">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-3 text-sm">
          <span className="w-28 shrink-0 font-medium text-slate-700">{fmt.label(k)}</span>
          <div className="h-2.5 flex-1 rounded-full bg-slate-100">
            <div className={`h-2.5 rounded-full ${categoryBar[k] ?? "bg-slate-400"}`} style={{ width: `${Math.max(4, (v / max) * 100)}%` }} />
          </div>
          <span className="w-10 text-right font-medium tabular-nums text-slate-700">{v}</span>
        </div>
      ))}
    </div>
  );
}

function Daily({ days }: { days: { date: string; total: number; blocked: number; redacted: number }[] }) {
  if (!days.length) return <p className="py-6 text-center text-sm text-slate-500">No activity yet.</p>;
  const byDate = new Map(days.map((d) => [d.date, d]));
  const latest = new Date(`${days[days.length - 1].date}T12:00:00Z`);
  const slots: { date: string; total: number; blocked: number; redacted: number }[] = [];
  for (let i = 6; i >= 0; i--) {
    const dt = new Date(latest.getTime() - i * 86400000);
    const key = dt.toISOString().slice(0, 10);
    slots.push(byDate.get(key) ?? { date: key, total: 0, blocked: 0, redacted: 0 });
  }
  const max = Math.max(1, ...slots.map((d) => d.total));
  return (
    <div>
      <div className="mb-3 flex items-center justify-end gap-4 text-[11px] text-slate-500">
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-xs bg-red-500" />Blocked</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-xs bg-amber-400" />Redacted</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-xs bg-blue-600" />Allowed / Warned</span>
      </div>
      <div className="flex h-32 items-end justify-between gap-2 border-b border-slate-100 pb-2" role="img" aria-label="Inspections per day">
        {slots.map((d) => (
          <div
            key={d.date}
            className="flex flex-1 flex-col items-center gap-1.5"
            title={`${d.date}: ${d.total} inspections (${d.blocked} blocked, ${d.redacted} redacted)`}
          >
            {d.total > 0 ? (
              <div
                className="flex w-full max-w-9 flex-col-reverse overflow-hidden rounded-t-md shadow-2xs"
                style={{ height: `${Math.max(14, (d.total / max) * 96)}px` }}
              >
                <div className="bg-red-500" style={{ height: `${(d.blocked / d.total) * 100}%` }} />
                <div className="bg-amber-400" style={{ height: `${(d.redacted / d.total) * 100}%` }} />
                <div className="flex-1 bg-blue-600" />
              </div>
            ) : (
              <div className="h-1.5 w-full max-w-9 rounded-full bg-slate-100" />
            )}
            <span className="text-[10px] font-mono tabular-nums text-slate-400">{d.date.slice(5)}</span>
          </div>
        ))}
      </div>
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
        subtitle="Every prompt, retrieved document, tool call and model answer that passed through the shield: what was found, what was decided, and how the audit hash chain verified it."
        actions={
          <div className="flex items-center gap-2">
            {s.chain && (
              <Badge tone={s.chain.valid ? "success" : "danger"}>
                {s.chain.valid ? `Audit chain verified (${s.chain.checked})` : "Audit chain broken"}
              </Badge>
            )}
            <Link href="/inspect"><Button>Inspect text</Button></Link>
          </div>
        }
      />
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Inspections" value={fmt.num(s.inspections)} hint={`${s.ai_reviews} with verified AI review`} />
        <Stat label="Blocked" value={fmt.num(s.by_action.block ?? 0)} hint={`${pct(s.by_action.block ?? 0)} of all traffic`} />
        <Stat label="Redacted" value={fmt.num(s.by_action.redact ?? 0)} hint={`${pct(s.by_action.redact ?? 0)} pseudonymised`} />
        <Stat label="Average risk" value={s.avg_risk} hint={`${fmt.num(s.findings)} findings · ${s.feedback?.false_positive ?? 0} dismissed`} />
      </div>
      <div className="mb-5 grid gap-5 lg:grid-cols-2">
        <Panel title="Findings by category" subtitle="Last 1,000 inspections, suppressed findings excluded."><Bars data={s.by_category} /></Panel>
        <Panel title="7-day inspection activity" subtitle="Daily volume by policy decision (blocked, redacted, allowed/warned)."><Daily days={s.daily} /></Panel>
      </div>
      <Panel title="Recent inspections" flush actions={<Link className="text-xs font-medium text-blue-700 hover:underline" href="/audit">Full audit log →</Link>}>
        <Table
          head={["Inspection", "Source", "Direction", "Decision", "Risk", "Findings", "Chain hash", "When"]}
          empty={<>Nothing yet. <Link className="font-medium text-blue-700 hover:underline" href="/inspect">Inspect some text</Link>.</>}
          rows={(recent.data ?? []).map((r) => [
            <Link key="i" href={`/audit/${r.id}`} className="font-mono text-xs font-medium text-blue-700 hover:underline">{r.id}</Link>,
            <span key="s" className="text-xs">{r.source}</span>,
            <span key="d" className="text-xs">{r.direction}</span>,
            <Badge key="a" tone={statusTone(r.action)}>{r.action}</Badge>,
            <span key="r" className="tabular-nums font-medium">{r.risk_score}</span>,
            <Legend key="c" counts={r.counts} />,
            <span key="h" className="font-mono text-[11px] text-slate-400">{(r.entry_hash ?? "").slice(0, 10) || "—"}</span>,
            <span key="w" className="whitespace-nowrap text-xs text-slate-500">{fmtDate(r.created_at)}</span>,
          ])}
        />
      </Panel>
    </>
  );
}
