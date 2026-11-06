"use client";
import Link from "next/link";
import { Badge, Button } from "./ui";

const PRESETS = [
  {
    title: "Support ticket (Rules + Verified AI)",
    path: "/inspect",
    badge: "Redact · Risk 98",
    tone: "warning" as const,
    desc: "Rules catch the email, phone, Luhn card number and IBAN in <10ms; the AI reviewer adds the customer account & address details, verified against the exact character span.",
  },
  {
    title: "Indirect injection + zero-width evasion",
    path: "/inspect",
    badge: "Block · Context",
    tone: "danger" as const,
    desc: "A retrieved product page hides an instruction inside an HTML comment and zero-width characters. The coordinate-preserving shadow view catches and blocks it.",
  },
  {
    title: "Guarded chat (Canary + Placeholder Restore)",
    path: "/guard",
    badge: "5-Step Gateway",
    tone: "success" as const,
    desc: "Replaces customer.demo@example.com with <<EMAIL_1>>, injects a per-call ZXQ- canary token, calls Gemini/Ollama, verifies output integrity, and restores the original email.",
  },
  {
    title: "Prompt Studio (Checked AI Rewrite)",
    path: "/prompt",
    badge: "5 Deterministic Checks",
    tone: "accent" as const,
    desc: "Scores a vague prompt across 5 dimensions and verifies the model's rewrite preserves every variable, invents no placeholders, and introduces zero sensitive data.",
  },
];

export function DemoModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-xs" onClick={onClose}>
      <div
        className="w-full max-w-2xl rounded-xl border border-slate-200 bg-white shadow-xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50/70 px-6 py-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Quick Demo Scenarios</h2>
            <p className="text-xs text-slate-500">Explore deterministic rule detection, shadow de-obfuscation, verified AI review, and guarded chat.</p>
          </div>
          <Button size="sm" variant="secondary" onClick={onClose}>Close</Button>
        </div>
        <div className="divide-y divide-slate-100 p-6 space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {PRESETS.map((p) => (
              <Link
                key={p.title}
                href={p.path}
                onClick={onClose}
                className="group rounded-lg border border-slate-200 p-4 transition-all hover:border-blue-300 hover:bg-blue-50/30"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-900 group-hover:text-blue-700">{p.title}</span>
                  <Badge tone={p.tone}>{p.badge}</Badge>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{p.desc}</p>
              </Link>
            ))}
          </div>
          <div className="pt-3 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-2">
            <span>Every inspection is recorded in a tamper-evident SHA-256 hash chain with zero raw text stored.</span>
            <Link href="/benchmarks" onClick={onClose} className="font-semibold text-blue-700 hover:underline">
              Run 41-sample + 90-mutation benchmark →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

