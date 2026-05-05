'use client';

/**
 * Compact dashboard pills for the AppShell topbar.
 *
 * Always visible (overflow-x-auto on small widths) so the user can
 * jump between dashboards without depending on the lg-only sidebar.
 */
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const ITEMS = [
  { href: '/dashboards/triage',      label: 'Triage',     hint: 'B — SOC' },
  { href: '/dashboards/remediation', label: 'Remediation', hint: 'D — Governance' },
  { href: '/dashboards/exposure',    label: 'Exposure',    hint: 'C — Asset' },
  { href: '/dashboards/executive',   label: 'Executive',   hint: 'A — CISO' },
];

export default function DashboardSwitcher() {
  const pathname = usePathname();

  return (
    <nav
      aria-label="Cambia dashboard"
      className="flex bg-gray-800/70 border border-gray-700 rounded-lg p-0.5 gap-0.5 overflow-x-auto max-w-full"
    >
      {ITEMS.map((it) => {
        const active = pathname === it.href;
        return (
          <Link
            key={it.href}
            href={it.href}
            aria-current={active ? 'page' : undefined}
            title={it.hint}
            className={`px-3 py-1 rounded-md text-xs font-medium whitespace-nowrap transition focus:outline-none ${
              active
                ? 'bg-indigo-600 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {it.label}
          </Link>
        );
      })}
      <Link
        href="/dashboards"
        title="Tutte le dashboard"
        className="px-2 py-1 rounded-md text-xs text-gray-500 hover:text-white border-l border-gray-700 ml-0.5 whitespace-nowrap"
      >
        ⊞
      </Link>
    </nav>
  );
}
