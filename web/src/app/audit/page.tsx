"use client";
import Link from "next/link";
import { useState } from "react";
import { Badge, ErrorBox, PageHeader, Panel, Select, Spinner, Table, fmtDate, statusTone } from "@/components/ui";
import { Legend } from "@/components/shield";
import { fmt, useApi } from "@/lib/api";

export default function AuditPage() {
  const [action, setAction] = useState("");
  const list = useApi<any[]>(`/v1/audit?limit=200${action ? `&action=${action}` : ""}`, { refetch: 10000 });
  const chain = useApi<any>("/v1/audit/verify", { refetch: 10000 });
  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Every inspection with its decision, masked findings, and SHA-256 hash chain link. The shield stores a SHA-256 of each text and its length, never the text or a raw value."
        actions={
          <div className="flex items-center gap-3">
            {chain.data && (
              <Badge tone={chain.data.valid ? "success" : "danger"}>
                {chain.data.valid
                  ? `Hash chain verified (${chain.data.checked} record${chain.data.checked === 1 ? "" : "s"})`
                  : `Hash chain broken at ${chain.data.broken_at}`}
              </Badge>
            )}
            <Select className="w-44" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Filter by decision">
              <option value="">All decisions</option>
              {["block", "redact", "warn", "allow"].map((a) => <option key={a} value={a}>{a}</option>)}
            </Select>
          </div>
        }
      />
      <ErrorBox error={list.error} />
      {!list.data && !list.error ? <Spinner /> : (
        <Panel flush>
          <Table
            head={["Inspection", "When", "Source", "Direction", "Type", "Policy", "Decision", "Risk", "Findings", "AI", "Chain hash", "Size", "Time"]}
            empty="No inspections yet."
            rows={(list.data ?? []).map((r) => [
              <Link key="i" href={`/audit/${r.id}`} className="font-mono text-xs font-medium text-blue-700 hover:underline">{r.id}</Link>,
              <span key="w" className="whitespace-nowrap text-xs text-slate-500">{fmtDate(r.created_at)}</span>,
              <span key="s">{r.source}</span>,
              <span key="d">{r.direction}</span>,
              <span key="t">{r.content_type}</span>,
              <span key="p" className="font-mono text-xs">{r.policy_id}</span>,
              <Badge key="a" tone={statusTone(r.action)}>{r.action}</Badge>,
              <span key="r" className="tabular-nums">{r.risk_score}</span>,
              <Legend key="c" counts={r.counts} />,
              <span key="ai">{r.ai_used ? "yes" : "—"}</span>,
              <span key="h" className="font-mono text-xs text-slate-500" title={r.entry_hash || ""}>{(r.entry_hash ?? "").slice(0, 10) || "—"}</span>,
              <span key="l" className="tabular-nums text-xs text-slate-500">{fmt.num(r.length)}</span>,
              <span key="ms" className="tabular-nums text-xs text-slate-500">{fmt.ms(r.duration_ms)}</span>,
            ])}
          />
        </Panel>
      )}
    </>
  );
}
