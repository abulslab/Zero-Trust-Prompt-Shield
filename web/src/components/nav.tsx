"use client";
import clsx from "clsx";
import Link from "next/link";
import { usePathname } from "next/navigation";

const groups = [
  {
    label: "Protect",
    items: [
      { href: "/", label: "Overview", match: (p: string) => p === "/" },
      { href: "/inspect", label: "Inspect", match: (p: string) => p.startsWith("/inspect") },
      { href: "/guard", label: "Guarded chat", match: (p: string) => p.startsWith("/guard") },
    ],
  },
  {
    label: "Improve",
    items: [{ href: "/prompt", label: "Prompt studio", match: (p: string) => p.startsWith("/prompt") }],
  },
  {
    label: "Govern",
    items: [
      { href: "/policies", label: "Policies", match: (p: string) => p.startsWith("/policies") },
      { href: "/audit", label: "Audit log", match: (p: string) => p.startsWith("/audit") },
      { href: "/review", label: "Review", match: (p: string) => p.startsWith("/review") },
      { href: "/benchmarks", label: "Benchmarks", match: (p: string) => p.startsWith("/benchmarks") },
    ],
  },
];

export function Nav() {
  const path = usePathname() ?? "/";
  return (
    <aside className="w-full md:w-52 shrink-0 rounded-xl border border-slate-200 bg-white p-3 shadow-xs">
      {groups.map((g) => (
        <div key={g.label} className="mb-2 last:mb-0">
          <div className="mb-1 mt-1 px-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{g.label}</div>
          <nav className="space-y-1">
            {g.items.map((i) => {
              const active = i.match(path);
              return (
                <Link
                  key={i.href}
                  href={i.href}
                  className={clsx(
                    "flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    active ? "bg-blue-50 text-blue-700 shadow-2xs font-semibold" : "text-slate-600 hover:bg-slate-50 hover:text-slate-900",
                  )}
                >
                  {i.label}
                </Link>
              );
            })}
          </nav>
        </div>
      ))}
    </aside>
  );
}
