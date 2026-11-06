"use client";
import { useState } from "react";
import { Button, Checkbox, ErrorBox, Field, Notice, PageHeader, Panel, Select, Stat, Tabs, Textarea } from "@/components/ui";
import { AiPanel, CopyButton, DecisionBanner, FindingsTable, Highlighted, Legend } from "@/components/shield";
import { type Inspection, fmt, post, useAction, useApi } from "@/lib/api";
import { samples } from "@/lib/samples";

const directions = [
  { v: "input", l: "Prompt being sent (input)" },
  { v: "context", l: "Retrieved document or tool output (context)" },
  { v: "output", l: "Model answer (output)" },
];

export default function InspectPage() {
  const policies = useApi<any[]>("/v1/policies");
  const meta = useApi<any>("/v1/meta");
  const [text, setText] = useState(samples[0].text);
  const [direction, setDirection] = useState(samples[0].direction);
  const [contentType, setContentType] = useState(samples[0].content_type);
  const [policy, setPolicy] = useState("");
  const [useAi, setUseAi] = useState(true);
  const [tab, setTab] = useState("findings");
  const [picked, setPicked] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState("");

  const run = useAction((body: any) => post<Inspection>("/v1/inspect", body), ["/v1/audit", "/v1/stats"]);
  const redact = useAction((body: any) => post<any>("/v1/redact", body));
  const r = run.data;

  const go = () => {
    setSubmitted(text);
    setPicked(null);
    redact.reset();
    run.mutate({ content: text, direction, content_type: contentType, policy: policy || null, ai: useAi ? "auto" : "off" });
  };
  const load = (id: string) => {
    const s = samples.find((x) => x.id === id);
    if (s) { setText(s.text); setDirection(s.direction); setContentType(s.content_type); run.reset(); redact.reset(); }
  };

  return (
    <>
      <PageHeader
        title="Inspect"
        subtitle="Check any text before it reaches a model, or after it leaves one: credentials, personal and financial data, internal infrastructure, obfuscated injections, and confidential content."
        actions={
          <Select className="w-68" defaultValue="" onChange={(e) => e.target.value && load(e.target.value)} aria-label="Load an example">
            <option value="">Load an example…</option>
            {samples.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </Select>
        }
      />

      <Panel className="mb-5">
        <Field label="Text under inspection" hint={`${fmt.num(text.length)} characters · inspected in memory, never stored (audit log records SHA-256 + masked previews only).`}>
          <Textarea rows={r ? 4 : 6} className="font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
        </Field>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Direction">
            <Select value={direction} onChange={(e) => setDirection(e.target.value)}>
              {directions.map((d) => <option key={d.v} value={d.v}>{d.l}</option>)}
            </Select>
          </Field>
          <Field label="Content type">
            <Select value={contentType} onChange={(e) => setContentType(e.target.value)}>
              {["text", "prompt", "code", "diff", "json"].map((c) => <option key={c} value={c}>{c}</option>)}
            </Select>
          </Field>
          <Field label="Policy">
            <Select value={policy} onChange={(e) => setPolicy(e.target.value)}>
              <option value="">Default ({meta.data?.default_policy ?? "balanced"})</option>
              {policies.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </Field>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <Checkbox checked={useAi} onChange={setUseAi} disabled={!meta.data?.ai?.available}
            label="Semantic review with AI"
            hint={meta.data?.ai?.available ? `Uses ${meta.data.ai.provider} (${meta.data.ai.model}); rule findings are redacted before the model sees the text.` : "No model configured on the server: deterministic rules only."} />
          <Button onClick={go} disabled={!text.trim() || run.isPending}>{run.isPending ? "Inspecting…" : "Inspect"}</Button>
        </div>
      </Panel>

      <ErrorBox error={run.error} />

      {r && (
        <div className="space-y-4">
          <DecisionBanner r={r} />
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Findings" value={r.findings.filter((f) => !f.suppressed).length} hint={<Legend counts={r.counts} />} />
            <Stat label="Policy" value={<span className="text-lg">{r.decision.policy_id}</span>} hint={`direction: ${r.direction}`} />
            <Stat label="AI review" value={<span className="text-lg">{r.ai.used ? `${r.ai.verified} / ${r.ai.proposed}` : "Off"}</span>} hint={r.ai.used ? "verified / proposed" : r.ai.error ?? "rules only"} />
            <Stat label="Time" value={<span className="text-lg">{fmt.ms(Object.values(r.timings_ms).reduce((a, b) => a + b, 0))}</span>} hint={Object.entries(r.timings_ms).map(([k, v]) => `${k} ${v}ms`).join(" · ")} />
          </div>

          <Panel flush>
            <div className="px-5 pt-3">
              <Tabs value={tab} onChange={setTab} tabs={[
                { id: "findings", label: `Findings (${r.findings.length})` },
                { id: "text", label: "Highlighted text" },
                { id: "safe", label: "Safe version" },
              ]} />
            </div>
            {tab === "findings" && <FindingsTable findings={r.findings} inspectionId={r.id} selected={picked} />}
            {tab === "text" && (
              <div className="px-5 pb-4">
                <Highlighted text={submitted} findings={r.findings} onPick={(id) => { setPicked(id); setTab("findings"); }} />
                <p className="mt-2 text-xs text-slate-500">Click any highlight to inspect its rule, severity, and remediation guidance.</p>
              </div>
            )}
            {tab === "safe" && (
              <div className="space-y-4 px-5 pb-5">
                {r.redacted ? (
                  <>
                    <div className="flex items-center justify-between"><span className="text-sm font-medium text-slate-700">Masked by policy</span><CopyButton text={r.redacted} /></div>
                    <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs">{r.redacted}</pre>
                  </>
                ) : <Notice>The policy did not require any redaction.</Notice>}
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="secondary" onClick={() => redact.mutate({ content: submitted, direction, content_type: contentType, policy: policy || null, mode: "placeholder" })}>
                    Create placeholder version (&lt;&lt;EMAIL_1&gt;&gt;)
                  </Button>
                  <Button variant="secondary" onClick={() => redact.mutate({ content: submitted, direction, content_type: contentType, policy: policy || null, mode: "synthetic" })}>
                    Create synthetic version (RFC-reserved)
                  </Button>
                  <span className="text-xs text-slate-500">Reversible mapping is returned to you only; the server stores nothing.</span>
                </div>
                {redact.data && (
                  <div className="grid gap-4 lg:grid-cols-2">
                    <div>
                      <div className="mb-1 flex items-center justify-between"><span className="text-sm font-medium text-slate-700">Send this</span><CopyButton text={redact.data.redacted} /></div>
                      <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs">{redact.data.redacted}</pre>
                    </div>
                    <div>
                      <div className="mb-1 flex items-center justify-between"><span className="text-sm font-medium text-slate-700">Mapping (private)</span><CopyButton text={JSON.stringify(redact.data.mapping, null, 2)} /></div>
                      <pre className="max-h-80 overflow-auto rounded-md border border-amber-200 bg-amber-50 p-3 font-mono text-xs">{Object.keys(redact.data.mapping).map((k) => `${k} = ${"•".repeat(8)}`).join("\n") || "(empty)"}</pre>
                      <p className="mt-1 text-xs text-slate-500">Values are hidden on screen; Copy puts the full mapping on your clipboard.</p>
                    </div>
                  </div>
                )}
                <ErrorBox error={redact.error} />
              </div>
            )}
          </Panel>
          <AiPanel ai={r.ai} />
        </div>
      )}
    </>
  );
}
