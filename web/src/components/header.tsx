"use client";
import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";
import { useApi } from "@/lib/api";
import { DemoModal } from "./demo-modal";

export function Header() {
  const pathname = usePathname();
  const meta = useApi<any>("/v1/meta");
  const [demoOpen, setDemoOpen] = useState(false);
  const isSettings = pathname?.startsWith("/settings");
  const ai = meta.data?.ai;

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-slate-200 bg-white/95 backdrop-blur-xs">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="group flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-700 text-white shadow-xs group-hover:bg-blue-800 transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                <path fillRule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM13.707 8.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="flex flex-col justify-center">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-slate-900 group-hover:text-blue-700 transition-colors">
                  Zero-Trust Prompt Shield
                </span>
                <span className="rounded-sm bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                  v{meta.data?.version ?? "1.0.2"}
                </span>
              </div>
              <p className="text-xs font-medium text-slate-500">
                AI proposes, the engine verifies · Zero raw text stored
              </p>
            </div>
          </Link>

          <div className="flex items-center gap-2.5 text-xs">
            <span
              title={
                meta.error
                  ? "API not reachable"
                  : ai?.available
                    ? `Semantic review, optimiser and guard use ${ai.provider} (${ai.model})`
                    : "No model configured: deterministic rules only"
              }
              className={clsx(
                "hidden sm:inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-medium shadow-2xs",
                meta.error
                  ? "border-red-200 bg-red-50 text-red-700"
                  : ai?.available
                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                    : "border-slate-200 bg-white text-slate-600",
              )}
            >
              <span
                className={clsx(
                  "h-2 w-2 rounded-full",
                  meta.error ? "bg-red-500" : ai?.available ? "bg-emerald-600" : "bg-slate-400",
                )}
              />
              {meta.error
                ? "API offline"
                : ai?.available
                  ? `AI: ${ai.provider} · ${ai.model}`
                  : meta.data
                    ? "Rules only"
                    : "Connecting…"}
            </span>

            <button
              type="button"
              onClick={() => setDemoOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium text-slate-700 shadow-2xs transition-colors hover:bg-slate-50 hover:text-slate-900 cursor-pointer"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-blue-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
              </svg>
              <span>Demo</span>
            </button>

            <Link
              href="/settings"
              className={clsx(
                "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-medium transition-colors shadow-2xs",
                isSettings
                  ? "border-blue-200 bg-blue-50 font-semibold text-blue-700"
                  : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50 hover:text-slate-900",
              )}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
              </svg>
              <span>Settings</span>
            </Link>
          </div>
        </div>
      </header>
      <DemoModal open={demoOpen} onClose={() => setDemoOpen(false)} />
    </>
  );
}
