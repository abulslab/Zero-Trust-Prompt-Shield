"use client";
import clsx from "clsx";
import { useState } from "react";
import { Badge, Button, Checkbox, ErrorBox, Field, Input, Notice, PageHeader, Panel, Textarea, statusTone } from "@/components/ui";
import { CopyButton } from "@/components/shield";
import { type Lint, fmt, post, useAction, useApi } from "@/lib/api";
import { promptSamples } from "@/lib/samples";

function Score({ lint, label }: { lint: Lint; label: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-4 py-3">
      <div className="text-xs font-medium text-slate-500">{label}</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className="text-2xl font-semibold tabular-nums text-slate-900">{lint.score}</span>
        <Badge tone={statusTone(lint.grade)}>Grade {lint.grade}</Badge>
      </div>
      <div className="mt-3 space-y-1.5">
        {Object.entries(lint.dimensions).map(([k, v]) => (
          <div key={k} className="flex items-center gap-2 text-xs">
            <span className="w-20 text-slate-500">{fmt.label(k)}</span>
            <div className="h-1.5 flex-1 rounded-full bg-slate-100"><div className={clsx("h-1.5 rounded-full", v >= 85 ? "bg-green-600" : v >= 65 ? "bg-amber-500" : "bg-red-500")} style={{ width: `${v}%` }} /></div>
            <span className="w-7 text-right tabular-nums text-slate-600">{v}</span>
          </div>
        ))}
      </div>
      <div className="mt-2 text-xs text-slate-500">{lint.stats.words} words · ~{lint.stats.estimated_tokens} tokens</div>
    </div>
  );
}

export default function PromptStudio() {
  const meta = useApi<any>("/v1/meta");
  const [prompt, setPrompt] = useState(promptSamples[0]);
  const [goal, setGoal] = useState("");
  const [useAi, setUseAi] = useState(true);
  const lint = useAction((p: string) => post<any>("/v1/prompt/lint", { prompt: p }));
  const opt = useAction((b: any) => post<any>("/v1/prompt/optimize", b));
  const l: Lint | undefined = lint.data?.lint;
  const o = opt.data;

  return (
    <>
      <PageHeader
        title="Prompt studio"
        subtitle="Score a prompt on clarity, specificity, structure, safety and efficiency, get a fix for each issue, and generate an improved version that is checked before it is shown."
      />
      <Panel className="mb-6">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {promptSamples.map((p, i) => <Button key={i} size="sm" variant="ghost" onClick={() => { setPrompt(p); lint.reset(); opt.reset(); }}>Example {i + 1}</Button>)}
        </div>
        <Field label="Prompt">
          <Textarea rows={7} value={prompt} onChange={(e) => setPrompt(e.target.value)} className="font-mono text-xs" spellCheck={false} />
        </Field>
        <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end">
          <Field label="Goal of the rewrite (optional)" hint="For example: make it work well for a small local model, or make the output machine-readable.">
            <Input value={goal} onChange={(e) => setGoal(e.target.value)} maxLength={500} />
          </Field>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => lint.mutate(prompt)} disabled={!prompt.trim() || lint.isPending}>{lint.isPending ? "Scoring…" : "Score prompt"}</Button>
            <Button onClick={() => { lint.mutate(prompt); opt.mutate({ prompt, goal: goal || null, ai: useAi }); }} disabled={!prompt.trim() || opt.isPending}>{opt.isPending ? "Optimising…" : "Optimise"}</Button>
          </div>
        </div>
        <div className="mt-3">
          <Checkbox checked={useAi} onChange={setUseAi} disabled={!meta.data?.ai?.available} label="Let the model propose the rewrite"
            hint={meta.data?.ai?.available ? "The model sees the prompt with sensitive values replaced by placeholders; its rewrite must pass every check or the structured rewrite is used." : "No model configured: a deterministic structured rewrite is used."} />
        </div>
      </Panel>
      <ErrorBox error={lint.error ?? opt.error} />

      {l && (
        <div className="mb-6 grid gap-6 lg:grid-cols-[18rem_1fr]">
          <Score lint={l} label="Current prompt" />
          <Panel title={`Issues (${l.issues.length})`} subtitle="Heuristic checks: each flags a likely problem and how to fix it." flush>
            {l.issues.length === 0 ? <p className="px-5 py-6 text-sm text-slate-500">No issues found.</p> : (
              <ul className="divide-y divide-slate-100">
                {l.issues.map((i, n) => (
                  <li key={n} className="px-5 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={statusTone(i.severity)}>{i.severity}</Badge>
                      <span className="text-sm font-medium text-slate-900">{i.title}</span>
                      <span className="font-mono text-[11px] text-slate-400">{i.id} · {i.dimension}</span>
                    </div>
                    <p className="mt-1 text-sm text-slate-600">{i.message}</p>
                    <p className="mt-1 text-sm text-blue-800"><span className="font-semibold">Fix: </span>{i.suggestion}</p>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      )}

      {o && (
        <div className="space-y-6">
          {o.rejected_model_rewrite && <Notice tone="warning">The model&apos;s rewrite was rejected ({o.model_error}). Showing the structured rewrite instead.</Notice>}
          {!o.rejected_model_rewrite && o.model_error && <Notice tone="muted">Model not used: {o.model_error}</Notice>}
          <div className="grid gap-6 lg:grid-cols-[18rem_1fr]">
            <div className="space-y-3">
              <Score lint={o.after} label={`Improved (${o.engine === "model" ? "model rewrite" : "structured rewrite"})`} />
              <Panel title="Checks" subtitle="All must pass before a model rewrite is shown.">
                <ul className="space-y-2">
                  {o.checks.map((c: any) => (
                    <li key={c.name} className="flex items-start gap-2 text-xs">
                      <span className={clsx("mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white", c.passed ? "bg-green-600" : "bg-red-600")}>{c.passed ? "✓" : "✗"}</span>
                      <span><span className="font-medium text-slate-800">{c.name}</span><span className="block text-slate-500">{c.detail}</span></span>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
            <Panel title="Improved prompt" actions={<><CopyButton text={o.safe_rewrite} label="Copy safe version" /><CopyButton text={o.rewrite} /></>}
              subtitle={o.model ? `Proposed by ${o.model.provider} · ${o.model.model} in ${fmt.ms(o.model.latency_ms)}` : "Deterministic structured rewrite"}>
              <pre className="max-h-[30rem] overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">{o.rewrite}</pre>
              {o.changes.length > 0 && (
                <div className="mt-4">
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-slate-400">What changed</h3>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm text-slate-700">{o.changes.map((c: string) => <li key={c}>{c}</li>)}</ul>
                </div>
              )}
              {o.assumptions.length > 0 && (
                <div className="mt-3">
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-slate-400">Assumptions to confirm</h3>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm text-slate-700">{o.assumptions.map((c: string) => <li key={c}>{c}</li>)}</ul>
                </div>
              )}
              {o.notes.map((n: string) => <p key={n} className="mt-3 text-xs text-slate-500">{n}</p>)}
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
