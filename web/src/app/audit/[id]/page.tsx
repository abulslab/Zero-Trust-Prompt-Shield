"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ErrorBox, PageHeader, Panel, Spinner, fmtDate } from "@/components/ui";
import { AiPanel, DecisionBanner, FindingsTable, Legend } from "@/components/shield";
import { type Inspection, fmt, useApi } from "@/lib/api";

export default function AuditItem() {
  const { id } = useParams<{ id: string }>();
  const item = useApi<Inspection & { source: string; content_sha256: string }>(id ? `/v1/audit/${id}` : null);
  if (item.error) return <><PageHeader title="Inspection" /><ErrorBox error={item.error} /></>;
  if (!item.data) return <Spinner />;
  const r = item.data;
  return (
    <>
      <PageHeader
        title={<span className="font-mono">{r.id}</span>}
        subtitle={<>{fmtDate(r.created_at)} · {r.source} · {r.direction} · {r.content_type} · {fmt.num(r.length)} characters · <Link className="text-blue-700 hover:underline" href="/audit">back to the audit log</Link></>}
      />
      <div className="space-y-6">
        <DecisionBanner r={r} />
        <Panel title="Record" subtitle="What the shield keeps about this text.">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div><dt className="text-xs text-slate-500">SHA-256 of the text</dt><dd className="break-all font-mono text-xs">{r.content_sha256}</dd></div>
            <div><dt className="text-xs text-slate-500">Findings</dt><dd><Legend counts={r.counts} /></dd></div>
            <div><dt className="text-xs text-slate-500">Summary</dt><dd>{r.summary}</dd></div>
            <div><dt className="text-xs text-slate-500">Timings</dt><dd className="text-xs">{Object.entries(r.timings_ms).map(([k, v]) => `${k} ${v}ms`).join(" · ")}</dd></div>
          </dl>
        </Panel>
        <Panel title="Findings" subtitle="Values are masked; the original text was not stored." flush>
          <FindingsTable findings={r.findings} inspectionId={r.id} />
        </Panel>
        <AiPanel ai={r.ai} />
      </div>
    </>
  );
}
