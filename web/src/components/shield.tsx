"use client";
import clsx from "clsx";
import { useState } from "react";
import { Badge, Button, Panel, statusTone, Table } from "@/components/ui";
import { type Finding, type Inspection, fmt, post, useAction } from "@/lib/api";

// One colour per category, used for highlights and legends everywhere.
export const categoryClass: Record<string, string> = {
  secret: "bg-red-100 text-red-900 ring-red-300",
  financial: "bg-rose-100 text-rose-900 ring-rose-300",
  pii: "bg-amber-100 text-amber-900 ring-amber-300",
  network: "bg-sky-100 text-sky-900 ring-sky-300",
  injection: "bg-violet-100 text-violet-900 ring-violet-300",
  obfuscation: "bg-fuchsia-100 text-fuchsia-900 ring-fuchsia-300",
  exfiltration: "bg-purple-100 text-purple-900 ring-purple-300",
  confidential: "bg-slate-200 text-slate-900 ring-slate-400",
};

// Solid fills for charts (the highlight colours above are too pale for thin bars).
export const categoryBar: Record<string, string> = {
  secret: "bg-red-600", financial: "bg-rose-500", pii: "bg-amber-500", network: "bg-sky-600",
  injection: "bg-violet-600", obfuscation: "bg-fuchsia-600", exfiltration: "bg-purple-700", confidential: "bg-slate-600",
};

export const actionCopy: Record<string, { title: string; body: string }> = {
  allow: { title: "Safe to send", body: "Nothing in this text needs attention under the selected policy." },
  warn: { title: "Allowed, with warnings", body: "Review the findings below before sending." },
  redact: { title: "Redact before sending", body: "Sensitive values must be replaced. The redacted version below is safe to send." },
  block: { title: "Blocked", body: "This text must not be sent as it is. Fix the findings below." },
};

export function DecisionBanner({ r }: { r: Inspection }) {
  const a = r.decision.action;
  const tone = { allow: "border-green-200 bg-green-50", warn: "border-blue-200 bg-blue-50", redact: "border-amber-200 bg-amber-50", block: "border-red-200 bg-red-50" }[a] ?? "border-slate-200 bg-white";
  return (
    <div className={clsx("flex flex-wrap items-center justify-between gap-4 rounded-lg border px-5 py-4", tone)}>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <Badge tone={statusTone(a)}>{a.toUpperCase()}</Badge>
          <h2 className="text-base font-semibold text-slate-900">{actionCopy[a]?.title}</h2>
        </div>
        <p className="mt-1 text-sm text-slate-600">{r.decision.reasons[0] ?? actionCopy[a]?.body}</p>
        {r.decision.reasons.length > 1 && (
          <ul className="mt-1 list-disc pl-5 text-xs text-slate-600">{r.decision.reasons.slice(1).map((x) => <li key={x}>{x}</li>)}</ul>
        )}
      </div>
      <RiskMeter score={r.decision.risk_score} />
    </div>
  );
}

export function RiskMeter({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-600" : score >= 50 ? "bg-amber-500" : score >= 20 ? "bg-blue-600" : "bg-green-600";
  return (
    <div className="w-40" aria-label={`Risk score ${score} of 100`}>
      <div className="flex items-baseline justify-between text-xs text-slate-500">
        <span>Risk</span>
        <span className="text-xl font-semibold tabular-nums text-slate-900">{score}<span className="text-xs font-normal text-slate-400">/100</span></span>
      </div>
      <div className="mt-1 h-1.5 w-full rounded-full bg-slate-200">
        <div className={clsx("h-1.5 rounded-full", color)} style={{ width: `${Math.max(2, score)}%` }} />
      </div>
    </div>
  );
}

// Renders the text with each finding highlighted. Positions come from the API, so nothing is re-searched here.
export function Highlighted({ text, findings, onPick }: { text: string; findings: Finding[]; onPick?: (id: string) => void }) {
  const sorted = [...findings].filter((f) => !f.suppressed).sort((a, b) => a.span.start - b.span.start);
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((f, i) => {
    if (f.span.start < cursor) return;
    parts.push(<span key={`t${i}`}>{text.slice(cursor, f.span.start)}</span>);
    parts.push(
      <mark key={`m${i}`} title={`${f.title} · ${f.severity} · ${f.action}`} onClick={() => onPick?.(f.id)}
        className={clsx("cursor-pointer rounded-sm px-0.5 ring-1", categoryClass[f.category] ?? "bg-yellow-100 ring-yellow-300")}>
        {text.slice(f.span.start, f.span.end)}
      </mark>,
    );
    cursor = f.span.end;
  });
  parts.push(<span key="end">{text.slice(cursor)}</span>);
  return <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">{parts}</pre>;
}

export function Legend({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts);
  if (!entries.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([c, n]) => (
        <span key={c} className={clsx("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ring-1", categoryClass[c])}>
          {fmt.label(c)} <span className="tabular-nums">{n}</span>
        </span>
      ))}
    </div>
  );
}

export function FindingsTable({ findings, inspectionId, selected }: { findings: Finding[]; inspectionId?: string; selected?: string | null }) {
  const [open, setOpen] = useState<string | null>(null);
  const [marked, setMarked] = useState<Record<string, string>>({});
  const fb = useAction((f: Finding & { verdict: string }) =>
    post("/v1/feedback", { finding_id: f.id, rule_id: f.rule_id, verdict: f.verdict, preview: f.preview, inspection_id: inspectionId }), ["/v1/feedback"]);

  return (
    <Table
      head={["Line", "Finding", "Category", "Severity", "Action", "Value", ""]}
      empty="No findings."
      rows={findings.map((f) => {
        const expanded = open === f.id || selected === f.id;
        return [
          <span key="l" className="tabular-nums text-xs text-slate-500">{f.span.line}:{f.span.column}</span>,
          <div key="t" className="min-w-48">
            <button type="button" className="text-left font-medium text-slate-900 hover:text-blue-700" onClick={() => setOpen(expanded ? null : f.id)}>
              {f.title}{f.suppressed && <span className="ml-1.5 text-xs font-normal text-slate-400">(suppressed)</span>}
            </button>
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-[11px] text-slate-400">{f.rule_id}</span>
              {f.origin === "model" && <Badge tone="accent" title="Proposed by a model and verified against the exact text">AI, verified</Badge>}
            </div>
            {expanded && (
              <div className="mt-2 space-y-1.5 text-xs">
                <p className="text-slate-700">{f.message}</p>
                <p className="rounded-md border border-blue-100 bg-blue-50 px-2.5 py-1.5 text-blue-900"><span className="font-semibold">How to fix: </span>{f.guidance}</p>
                {f.tags.length > 0 && <div className="flex gap-1">{f.tags.map((t) => <Badge key={t} tone="muted">{t}</Badge>)}</div>}
                <p className="text-slate-500">Confidence {fmt.pct(f.confidence)}</p>
              </div>
            )}
          </div>,
          <span key="c" className={clsx("rounded px-1.5 py-0.5 text-[11px] font-medium ring-1", categoryClass[f.category])}>{fmt.label(f.category)}</span>,
          <Badge key="s" tone={statusTone(f.severity)}>{f.severity}</Badge>,
          <Badge key="a" tone={statusTone(f.action)}>{f.action}</Badge>,
          <code key="v" className="whitespace-nowrap font-mono text-xs text-slate-600">{f.preview}</code>,
          <div key="fb" className="flex justify-end whitespace-nowrap">
            {marked[f.id] || f.suppressed ? (
              <span className="text-xs text-slate-500">{marked[f.id] === "true_positive" ? "Confirmed" : "Suppressed"}</span>
            ) : (
              <div className="flex gap-1">
                <Button size="sm" variant="ghost" title="Confirm this is a real problem" onClick={() => fb.mutate({ ...f, verdict: "true_positive" }, { onSuccess: () => setMarked((m) => ({ ...m, [f.id]: "true_positive" })) })}>Real</Button>
                <Button size="sm" variant="ghost" title="Not a problem: suppress this exact value next time" onClick={() => fb.mutate({ ...f, verdict: "false_positive" }, { onSuccess: () => setMarked((m) => ({ ...m, [f.id]: "false_positive" })) })}>Dismiss</Button>
              </div>
            )}
          </div>,
        ];
      })}
    />
  );
}

export function AiPanel({ ai }: { ai: Inspection["ai"] }) {
  if (!ai.requested) return null;
  return (
    <Panel title="AI review" subtitle="The model proposes; only proposals whose evidence is an exact span of the text are kept. It never sees values the rules already found.">
      {!ai.used ? (
        <p className="text-sm text-slate-600">Not used: {ai.error ?? "no model configured"}. The rule-based result above stands on its own.</p>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap gap-4 text-sm">
            <span><span className="text-slate-500">Model</span> <span className="font-medium">{ai.provider} · {ai.model}</span></span>
            <span><span className="text-slate-500">Proposed</span> <span className="font-semibold tabular-nums">{ai.proposed}</span></span>
            <span><span className="text-slate-500">Verified</span> <span className="font-semibold tabular-nums text-green-700">{ai.verified}</span></span>
            <span><span className="text-slate-500">Rejected</span> <span className="font-semibold tabular-nums text-red-700">{ai.rejections.length}</span></span>
            <span><span className="text-slate-500">Latency</span> <span className="tabular-nums">{fmt.ms(ai.latency_ms)}</span></span>
          </div>
          {ai.rejections.length > 0 && (
            <ul className="space-y-1 text-xs">
              {ai.rejections.map((r, i) => (
                <li key={i} className="flex gap-2"><Badge tone="muted">{r.category}</Badge><span className="text-slate-600">{r.reason}</span>{r.evidence_preview && <code className="font-mono text-slate-400">{r.evidence_preview}</code>}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button size="sm" variant="secondary" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }); }}>
      {done ? "Copied" : label}
    </Button>
  );
}
