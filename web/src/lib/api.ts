"use client";
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5380";
const TOKEN_KEY = "promptshield_api_key";

// Optional: when the API runs with SHIELD_API_KEY, store it once in this browser (Settings page).
export function getToken() {
  if (typeof window === "undefined") return null;
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}
export function setToken(v: string | null) {
  try { if (v) localStorage.setItem(TOKEN_KEY, v); else localStorage.removeItem(TOKEN_KEY); } catch { /* storage blocked */ }
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: any) {
    super(message);
  }
}

export async function api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Shield-Source": "ui", ...(init.headers as any) };
  const token = getToken();
  if (token) headers["X-API-Key"] = token;
  if (init.json !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.json);
  }
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, `The Prompt Shield API is not reachable at ${API}. Start it with: promptshield serve`);
  }
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : Array.isArray(body?.detail) ? body.detail.map((d: any) => d.msg).join("; ") : res.statusText;
    throw new ApiError(res.status, detail || `Request failed (${res.status})`, body);
  }
  return body as T;
}

export const post = <T = any>(path: string, json: unknown) => api<T>(path, { method: "POST", json });

export function useApi<T = any>(path: string | null, opts: { refetch?: number } = {}) {
  return useQuery<T>({ queryKey: [path], queryFn: () => api<T>(path!), enabled: !!path, refetchInterval: opts.refetch });
}

export function useAction<TVars = any, TRes = any>(fn: (v: TVars) => Promise<TRes>, invalidate: string[] = []) {
  const qc = useQueryClient();
  return useMutation<TRes, ApiError, TVars>({
    mutationFn: fn,
    onSuccess: () => invalidate.forEach((k) => qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith(k) })),
  });
}

export const fmt = {
  pct: (n?: number | null) => (n == null ? "—" : `${Math.round(n * 100)}%`),
  num: (n?: number | null) => (n == null ? "—" : n.toLocaleString()),
  ms: (n?: number | null) => (n == null ? "—" : n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${n}ms`),
  label: (s: string) => ACRONYMS[s] ?? s.replace(/[._-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
};

const ACRONYMS: Record<string, string> = { pii: "PII" };

// Types returned by the API (the subset the UI uses).
export interface Finding {
  id: string; rule_id: string; detector: string; category: string; severity: string; confidence: number;
  title: string; message: string; guidance: string; origin: "rule" | "model"; tags: string[]; suppressed: boolean;
  action: string; preview: string; span: { start: number; end: number; line: number; column: number };
}
export interface Inspection {
  id: string; created_at: string; direction: string; content_type: string; length: number;
  decision: { action: string; risk_score: number; reasons: string[]; policy_id: string };
  findings: Finding[]; summary: string; redacted: string | null; counts: Record<string, number>;
  ai: { requested: boolean; used: boolean; provider: string | null; model: string | null; proposed: number; verified: number;
        rejections: { category: string; reason: string; evidence_preview: string }[]; error: string | null; latency_ms: number | null };
  timings_ms: Record<string, number>;
}
export interface LintIssue { id: string; dimension: string; severity: string; title: string; message: string; suggestion: string; evidence: string | null }
export interface Lint { score: number; grade: string; dimensions: Record<string, number>; issues: LintIssue[]; stats: Record<string, number>; variables: string[] }
