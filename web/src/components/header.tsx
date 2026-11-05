"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";
import { useApi } from "@/lib/api";

export function Header() {
  const pathname = usePathname();
  const meta = useApi<any>("/v1/meta");
  const isSettings = pathname?.startsWith("/settings");
  const ai = meta.data?.ai;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200 bg-white/95 backdrop-blur-xs">
      <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link href="/" className="group flex flex-col justify-center">
          <div className="flex items-center gap-2">
            <span className="text-base font-bold tracking-tight text-slate-900 group-hover:text-blue-600 transition-colors">
              Zero-Trust Prompt Shield
            </span>
            <span className="rounded-sm bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
              v{meta.data?.version ?? "1.0"}
            </span>
          </div>
          <p className="text-xs font-medium text-slate-500">AI proposes, the engine verifies</p>
        </Link>

        <div className="flex items-center gap-2.5 text-xs">
          <span
            title={meta.error ? "API not reachable" : ai?.available ? `Semantic review and optimisation use ${ai.provider} (${ai.model})` : "No model configured: rules only"}
            className={clsx(
              "hidden sm:inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-medium",
              meta.error ? "border-red-200 bg-red-50 text-red-700" : ai?.available ? "border-green-200 bg-green-50 text-green-800" : "border-slate-200 bg-white text-slate-600",
            )}
          >
            <span className={clsx("h-1.5 w-1.5 rounded-full", meta.error ? "bg-red-500" : ai?.available ? "bg-green-600" : "bg-slate-400")} />
            {meta.error ? "API offline" : ai?.available ? `AI: ${ai.provider}` : meta.data ? "Rules only" : "Connecting…"}
          </span>
          <Link
            href="/settings"
            className={clsx(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-colors border shadow-2xs",
              isSettings ? "bg-blue-50 border-blue-200 text-blue-700 font-semibold" : "bg-white border-slate-200 text-slate-700 hover:bg-slate-50 hover:text-slate-900",
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
  );
}
