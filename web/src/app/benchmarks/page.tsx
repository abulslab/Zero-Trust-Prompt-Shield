"use client";
import { Badge, Button, ErrorBox, Notice, PageHeader, Panel, Stat, Table } from "@/components/ui";
import { fmt, post, useAction } from "@/lib/api";

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

export default function Benchmarks() {
  const run = useAction(() => post<any>("/v1/benchmark", {}));
  const b = run.data;
  return (
    <>
      <PageHeader
        title="Benchmarks"
        subtitle="Precision, recall, and adversarial mutation resilience of the rule-based detectors on a labelled corpus that includes hard negatives: hashes, UUIDs, placeholders, environment references, removed diff lines, public IPs and security discussions."
        actions={<Button onClick={() => run.mutate(undefined)} disabled={run.isPending}>{run.isPending ? "Running…" : "Run benchmark"}</Button>}
      />
      <ErrorBox error={run.error} />
      {!b && !run.isPending && <Notice>Run the benchmark to measure the detectors and the adversarial mutation resilience suite. It takes under a second and uses no model.</Notice>}
      {b && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <Stat label="Samples" value={b.samples} hint={`${b.positives} positive · ${b.negatives} hard negatives`} />
            <Stat label="Precision" value={pct(b.overall.precision)} hint={`${b.overall.fp} false positive(s)`} />
            <Stat label="Recall" value={pct(b.overall.recall)} hint={`${b.overall.fn} missed`} />
            <Stat label="F1" value={b.overall.f1.toFixed(3)} hint={`in ${fmt.ms(b.duration_ms)}`} />
            {b.mutations && (
              <Stat
                label="Mutation resilience"
                value={pct(b.mutations.resilience)}
                hint={`${b.mutations.survived}/${b.mutations.tested} variants caught`}
              />
            )}
          </div>
          <Panel title="By category" flush>
            <Table
              head={["Category", "True pos.", "False pos.", "Missed", "Precision", "Recall", "F1"]}
              rows={b.categories.map((c: any) => [
                <span key="c" className="font-medium">{fmt.label(c.category)}</span>,
                <span key="tp" className="tabular-nums">{c.tp}</span>,
                <span key="fp" className="tabular-nums">{c.fp}</span>,
                <span key="fn" className="tabular-nums">{c.fn}</span>,
                <span key="p" className="tabular-nums">{pct(c.precision)}</span>,
                <span key="r" className="tabular-nums">{pct(c.recall)}</span>,
                <span key="f" className="tabular-nums">{c.f1.toFixed(3)}</span>,
              ])}
            />
          </Panel>
          {b.mutations?.by_mutation?.length > 0 && (
            <Panel title="Adversarial mutation resilience" flush>
              <Table
                head={["Mutation strategy", "Variants tested", "Detected", "Resilience"]}
                rows={b.mutations.by_mutation.map((m: any) => [
                  <span key="m" className="font-mono text-xs font-medium">{m.mutation}</span>,
                  <span key="t" className="tabular-nums">{m.tested}</span>,
                  <span key="s" className="tabular-nums">{m.survived}</span>,
                  <Badge key="r" tone={m.resilience >= 0.9 ? "success" : "warning"}>{pct(m.resilience)}</Badge>,
                ])}
              />
            </Panel>
          )}
          {b.misses.length > 0 && (
            <Panel title="Errors" flush>
              <Table head={["Sample", "Kind", "Category", "Rules"]}
                rows={b.misses.map((m: any, i: number) => [
                  <span key="s" className="font-mono text-xs">{m.sample}</span>,
                  <Badge key="k" tone={m.kind === "missed" ? "danger" : "warning"}>{m.kind}</Badge>,
                  <span key="c">{m.category}</span>,
                  <span key="r" className="font-mono text-xs">{(m.rules ?? []).join(", ") || "—"}<span className="hidden">{i}</span></span>,
                ])} />
            </Panel>
          )}
          <Notice tone="muted">{b.note} The corpus was written alongside the detectors, so these numbers show the rules behave as designed on known cases; they are not a measure of real-world accuracy. Add your own samples in backend/src/promptshield/eval/corpus.py.</Notice>
        </div>
      )}
    </>
  );
}
