"use client";
import { useState } from "react";
import { Badge, Button, ErrorBox, Field, Notice, PageHeader, Panel, Select, Textarea, statusTone } from "@/components/ui";
import { DecisionBanner, FindingsTable } from "@/components/shield";
import { fmt, post, useAction, useApi } from "@/lib/api";

type Msg = { role: string; content: string };

const STEPS = ["Inspect input and context", "Redact to placeholders", "Call the model", "Inspect the answer", "Restore placeholders"];

export default function GuardPage() {
  const meta = useApi<any>("/v1/meta");
  const policies = useApi<any[]>("/v1/policies");
  const [system, setSystem] = useState("You are a helpful support assistant. Answer in three short bullet points.");
  const [user, setUser] = useState("Draft a reply to maria.gonzalez@contoso-mail.com confirming her refund of the duplicate charge.");
  const [context, setContext] = useState("");
  const [policy, setPolicy] = useState("");
  const run = useAction((b: any) => post<any>("/v1/guard/chat", b), ["/v1/audit", "/v1/stats"]);
  const g = run.data;

  const send = () => {
    const messages: Msg[] = [];
    if (system.trim()) messages.push({ role: "system", content: system });
    if (context.trim()) messages.push({ role: "tool", content: context });
    messages.push({ role: "user", content: user });
    run.mutate({ messages, policy: policy || null });
  };

  const reached = g ? (g.status === "blocked_input" ? 1 : g.status === "model_unavailable" ? 2 : g.status === "blocked_output" ? 4 : 5) : 0;

  return (
    <>
      <PageHeader
        title="Guarded chat"
        subtitle="The shield as a gateway: it inspects the conversation and any untrusted context, swaps sensitive values for placeholders, calls the model, inspects the answer, then puts the values back. The model never sees the originals."
      />
      {meta.data && !meta.data.ai.available && (
        <div className="mb-4"><Notice tone="warning">No model is configured on the server, so the guard can inspect and redact but not answer. Set SHIELD_AI_PROVIDER (gemini, ollama, anthropic or openai).</Notice></div>
      )}
      <Panel className="mb-6">
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="System prompt"><Textarea rows={3} value={system} onChange={(e) => setSystem(e.target.value)} /></Field>
          <Field label="Untrusted context (optional)" hint="A retrieved document or tool result. Judged as context: instructions inside it block the request.">
            <Textarea rows={3} value={context} onChange={(e) => setContext(e.target.value)} placeholder="Paste a web page, search result or tool output…" />
          </Field>
        </div>
        <Field label="User message" className="mt-4"><Textarea rows={3} value={user} onChange={(e) => setUser(e.target.value)} /></Field>
        <div className="mt-4 flex flex-wrap items-end justify-between gap-3">
          <Field label="Policy" className="w-64">
            <Select value={policy} onChange={(e) => setPolicy(e.target.value)}>
              <option value="">Default ({meta.data?.default_policy ?? "balanced"})</option>
              {policies.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </Field>
          <Button onClick={send} disabled={!user.trim() || run.isPending}>{run.isPending ? "Sending…" : "Send through the shield"}</Button>
        </div>
      </Panel>
      <ErrorBox error={run.error} />

      {g && (
        <div className="space-y-6">
          <ol className="grid grid-cols-1 gap-2 sm:grid-cols-5">
            {STEPS.map((s, i) => {
              const done = i < reached;
              const stopped = i === reached && g.status !== "answered";
              return (
                <li key={s} className={`rounded-md border px-3 py-2 text-xs ${done ? "border-green-200 bg-green-50 text-green-800" : stopped ? "border-red-200 bg-red-50 text-red-800" : "border-slate-200 bg-white text-slate-400"}`}>
                  <span className="font-semibold">{i + 1}.</span> {s}
                </li>
              );
            })}
          </ol>
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-500">Outcome</span><Badge tone={statusTone(g.status)}>{fmt.label(g.status)}</Badge>
            {g.model && <span className="text-xs text-slate-500">{g.model.provider} · {g.model.model} · {fmt.ms(g.model.latency_ms)}</span>}
            {g.placeholders > 0 && <span className="text-xs text-slate-500">· {g.placeholders} value(s) hidden from the model</span>}
          </div>
          {g.error && <Notice tone="warning">{g.error}</Notice>}

          {g.answer && (
            <Panel title="Answer" subtitle="Placeholders restored after the answer passed inspection.">
              <div className="whitespace-pre-wrap text-sm leading-relaxed text-slate-800">{g.answer}</div>
            </Panel>
          )}

          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title={g.status === "model_unavailable" ? "What would be sent" : "What the model received"}
              subtitle={g.status === "model_unavailable" ? "Prepared payload; no model is configured, so nothing left the gateway." : "Exactly what left the gateway."}>
              {g.sent.length ? (
                <div className="space-y-2">
                  {g.sent.map((m: Msg, i: number) => (
                    <div key={i}><Badge tone="muted">{m.role}</Badge><pre className="mt-1 whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs">{m.content}</pre></div>
                  ))}
                </div>
              ) : <p className="text-sm text-slate-500">Nothing: the request was stopped before the model.</p>}
            </Panel>
            <div className="space-y-4">
              <DecisionBanner r={g.input} />
              {g.output && <DecisionBanner r={g.output} />}
            </div>
          </div>

          <Panel title="Input findings" flush><FindingsTable findings={g.input.findings} inspectionId={g.input.id} /></Panel>
          {g.output && g.output.findings.length > 0 && <Panel title="Answer findings" flush><FindingsTable findings={g.output.findings} inspectionId={g.output.id} /></Panel>}
        </div>
      )}
    </>
  );
}
