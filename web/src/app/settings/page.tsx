"use client";
import { useEffect, useState } from "react";
import { Badge, Button, Code, ErrorBox, Field, Input, PageHeader, Panel, Spinner } from "@/components/ui";
import { API, getToken, setToken, useApi } from "@/lib/api";

export default function SettingsPage() {
  const meta = useApi<any>("/v1/meta");
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => setKey(getToken() ?? ""), []);

  return (
    <>
      <PageHeader title="Settings" subtitle="Connection to the Prompt Shield API and what the server is configured to do. Server settings come from SHIELD_* environment variables." />
      <div className="space-y-6">
        <Panel title="Connection">
          <dl className="mb-4 text-sm"><dt className="text-xs text-slate-500">API URL (NEXT_PUBLIC_API_URL)</dt><dd className="font-mono">{API}</dd></dl>
          <Field label="API key" hint="Only needed when the server sets SHIELD_API_KEY. Stored in this browser only.">
            <div className="flex gap-2">
              <Input type="password" value={key} onChange={(e) => { setKey(e.target.value); setSaved(false); }} autoComplete="off" />
              <Button variant="secondary" onClick={() => { setToken(key.trim() || null); setSaved(true); meta.refetch(); }}>{saved ? "Saved" : "Save"}</Button>
            </div>
          </Field>
        </Panel>
        <ErrorBox error={meta.error} />
        {!meta.data && !meta.error && <Spinner />}
        {meta.data && (
          <>
            <Panel title="Server">
              <dl className="grid gap-4 text-sm sm:grid-cols-3">
                <div><dt className="text-xs text-slate-500">Version</dt><dd className="font-medium">{meta.data.version}</dd></div>
                <div><dt className="text-xs text-slate-500">Model</dt><dd>{meta.data.ai.available ? <span className="font-medium">{meta.data.ai.provider} · {meta.data.ai.model}</span> : <Badge>none: rules only</Badge>}</dd></div>
                <div><dt className="text-xs text-slate-500">Default policy</dt><dd className="font-mono">{meta.data.default_policy}</dd></div>
                <div><dt className="text-xs text-slate-500">Max text size</dt><dd className="tabular-nums">{meta.data.limits.max_chars.toLocaleString()} chars</dd></div>
                <div><dt className="text-xs text-slate-500">Max model input</dt><dd className="tabular-nums">{meta.data.limits.ai_max_input_chars.toLocaleString()} chars</dd></div>
                <div><dt className="text-xs text-slate-500">Rate limit</dt><dd className="tabular-nums">{meta.data.limits.rate_limit_per_minute}/min per client</dd></div>
                <div><dt className="text-xs text-slate-500">Authentication</dt><dd>{meta.data.auth ? <Badge tone="success">API key required</Badge> : <Badge tone="warning">open (local use)</Badge>}</dd></div>
              </dl>
              <div className="mt-4 flex flex-wrap gap-1.5">{meta.data.detectors.map((d: string) => <Badge key={d}>{d}</Badge>)}</div>
            </Panel>
            <Panel title="Turn on AI features" subtitle="Semantic review, prompt optimisation and the guard's model call. Keys stay on the server.">
              <Code>{`# .env in the folder you start the API from (never commit it)
SHIELD_AI_PROVIDER=gemini        # gemini | ollama | anthropic | openai | none
GEMINI_API_KEY=...
# SHIELD_AI_PROVIDER=ollama  SHIELD_OLLAMA_MODEL=qwen2.5:7b   (fully local)`}</Code>
            </Panel>
          </>
        )}
      </div>
    </>
  );
}
