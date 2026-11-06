"use client";
import clsx from "clsx";
import Link from "next/link";
import { usePathname } from "next/navigation";

const groups = [
  {
    label: "Protect",
    items: [
      {
        href: "/",
        label: "Overview",
        match: (p: string) => p === "/",
        icon: "M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z",
      },
      {
        href: "/inspect",
        label: "Inspect",
        match: (p: string) => p.startsWith("/inspect"),
        icon: "M9 9a2 2 0 114 0 2 2 0 01-4 0z M11 4a5 5 0 103.536 8.536l2.764 2.764a1 1 0 001.414-1.414l-2.764-2.764A5 5 0 0011 4z",
      },
      {
        href: "/guard",
        label: "Guarded chat",
        match: (p: string) => p.startsWith("/guard"),
        icon: "M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944z",
      },
    ],
  },
  {
    label: "Improve",
    items: [
      {
        href: "/prompt",
        label: "Prompt studio",
        match: (p: string) => p.startsWith("/prompt"),
        icon: "M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z",
      },
    ],
  },
  {
    label: "Govern",
    items: [
      {
        href: "/policies",
        label: "Policies",
        match: (p: string) => p.startsWith("/policies"),
        icon: "M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z",
      },
      {
        href: "/audit",
        label: "Audit log",
        match: (p: string) => p.startsWith("/audit"),
        icon: "M9 2a1 1 0 000 2h2a1 1 0 100-2H9z M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5z",
      },
      {
        href: "/review",
        label: "Review",
        match: (p: string) => p.startsWith("/review"),
        icon: "M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z",
      },
      {
        href: "/benchmarks",
        label: "Benchmarks",
        match: (p: string) => p.startsWith("/benchmarks"),
        icon: "M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z",
      },
    ],
  },
];

export function Nav() {
  const path = usePathname() ?? "/";
  return (
    <aside className="w-full md:w-56 md:sticky md:top-22 shrink-0 rounded-xl border border-slate-200 bg-white p-3 shadow-xs">
      {groups.map((g) => (
        <div key={g.label} className="mb-3 last:mb-0">
          <div className="mb-1 mt-1 px-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            {g.label}
          </div>
          <nav className="space-y-0.5">
            {g.items.map((i) => {
              const active = i.match(path);
              return (
                <Link
                  key={i.href}
                  href={i.href}
                  className={clsx(
                    "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors",
                    active
                      ? "bg-blue-50 text-blue-700 shadow-2xs font-semibold"
                      : "text-slate-600 hover:bg-slate-50 hover:text-slate-900",
                  )}
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className={clsx("h-4 w-4 shrink-0", active ? "text-blue-600" : "text-slate-400")}
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden
                  >
                    <path fillRule="evenodd" d={i.icon} clipRule="evenodd" />
                  </svg>
                  {i.label}
                </Link>
              );
            })}
          </nav>
        </div>
      ))}

      <div className="mt-4 border-t border-slate-100 pt-3 px-2.5 space-y-1.5 text-[11px] text-slate-500">
        <div className="font-semibold text-slate-700">Zero-Trust Guarantees</div>
        <div className="flex items-center justify-between">
          <span>Raw text stored</span>
          <span className="font-mono font-medium text-emerald-700">0 bytes</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Audit integrity</span>
          <span className="font-mono font-medium text-slate-700">SHA-256 chain</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Shadow view</span>
          <span className="font-mono font-medium text-slate-700">NFKC + ZW strip</span>
        </div>
      </div>
    </aside>
  );
}
