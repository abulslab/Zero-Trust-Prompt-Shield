"use client";
import { useState } from "react";
import { Badge, Code, ErrorBox, PageHeader, Panel, Spinner, Table, statusTone } from "@/components/ui";
import { useApi } from "@/lib/api";

function when(w: any) {
  const parts: string[] = [];
  if (w.category) parts.push(`category ${w.category.join(" | ")}`);
  if (w.direction) parts.push(`direction ${w.direction.join(" | ")}`);
  if (w.rule) parts.push(`rule ${w.rule.join(" | ")}*`);
  if (w.min_severity) parts.push(`severity ≥ ${w.min_severity}`);
  if (w.min_confidence != null) parts.push(`confidence ≥ ${w.min_confidence}`);
  if (w.origin) parts.push(`origin ${w.origin}`);
  return parts.join(", ") || "any finding";
}

export default function PoliciesPage() {
  const policies = useApi<any[]>("/v1/policies");
  const meta = useApi<any>("/v1/meta");
  const [sel, setSel] = useState<string | null>(null);
  if (policies.error) return <><PageHeader title="Policies" /><ErrorBox error={policies.error} /></>;
  if (!policies.data) return <Spinner />;
  const current = policies.data.find((p) => p.id === (sel ?? meta.data?.default_policy)) ?? policies.data[0];

  return (
    <>
      <PageHeader
        title="Policies"
        subtitle="Policy packs are YAML files: which detectors run, the organisation's restricted terms, and ordered rules that turn findings into allow, warn, redact or block. Add your own with SHIELD_POLICY_DIR."
      />
      <div className="grid gap-6 lg:grid-cols-[16rem_1fr]">
        <div className="space-y-2">
          {policies.data.map((p) => (
            <button key={p.id} type="button" onClick={() => setSel(p.id)}
              className={`w-full rounded-lg border px-4 py-3 text-left transition-colors ${p.id === current.id ? "border-blue-300 bg-blue-50" : "border-slate-200 bg-white hover:bg-slate-50"}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-slate-900">{p.name}</span>
                {p.id === meta.data?.default_policy && <Badge tone="accent">default</Badge>}
              </div>
              <div className="mt-0.5 font-mono text-[11px] text-slate-400">{p.id}{p.builtin ? "" : " · custom"}</div>
            </button>
          ))}
        </div>
        <div className="space-y-6">
          <Panel title={current.name} subtitle={current.description}>
            <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
              <div><dt className="text-xs text-slate-500">AI review</dt><dd className="font-medium">{current.ai_review}</dd></div>
              <div><dt className="text-xs text-slate-500">Block at risk</dt><dd className="font-medium tabular-nums">≥ {current.block_score}</dd></div>
              <div><dt className="text-xs text-slate-500">Default action</dt><dd><Badge tone={statusTone(current.default_action)}>{current.default_action}</Badge></dd></div>
              <div><dt className="text-xs text-slate-500">Restricted terms</dt><dd className="font-medium tabular-nums">{current.custom_terms.length}</dd></div>
            </dl>
            <div className="mt-4 flex flex-wrap gap-1.5">{current.detectors.map((d: string) => <Badge key={d}>{d}</Badge>)}</div>
          </Panel>
          <Panel title="Rules" subtitle="Each finding takes the action of the first rule it matches." flush>
            <Table
              head={["#", "When", "Action", "Reason"]}
              rows={current.rules.map((r: any, i: number) => [
                <span key="n" className="tabular-nums text-slate-400">{i + 1}</span>,
                <span key="w" className="font-mono text-xs">{when(r.when)}</span>,
                <Badge key="a" tone={statusTone(r.action)}>{r.action}</Badge>,
                <span key="r" className="text-xs text-slate-600">{r.reason ?? "—"}</span>,
              ])}
            />
          </Panel>
          <Panel title="Write your own" subtitle="Drop a file like this into the folder named by SHIELD_POLICY_DIR and restart the API.">
            <Code>{`id: example-org
name: Example Org external models
description: Customer identifiers and internal code names never leave.
ai_review: "auto"
block_score: 85
custom_terms: [Project-Alpha, ExampleCorp, ledger-v2]
rules:
  - when: { category: [secret, financial] }
    action: block
    reason: Credentials and payment data are blocked.
  - when: { category: confidential, rule: confidential.custom_term }
    action: block
    reason: Registered code names and customers stay internal.
  - when: { category: [pii, network] }
    action: redact`}</Code>
          </Panel>
        </div>
      </div>
    </>
  );
}
