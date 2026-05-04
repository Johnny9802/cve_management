'use client';

/**
 * Persistent sidebar navigation for the new IA.
 *
 * Sprint Dashboards 1 ships with a minimal set of routes — most entries
 * link back to the legacy single-page dashboard at `/` until the
 * remaining sections are ported in Sprint Dashboards 2-3.
 */
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAV = [
  {
    group: 'Dashboards',
    items: [
      { href: '/dashboards/triage',      label: 'SOC Triage',          badge: 'B' },
      { href: '/dashboards/remediation', label: 'Remediation',         badge: 'D' },
      { href: '/dashboards/exposure',    label: 'Asset Exposure',      badge: 'C', disabled: true, hint: 'Sprint Dashboards 3' },
      { href: '/dashboards/executive',   label: 'Executive',           badge: 'A', disabled: true, hint: 'Sprint Dashboards 3' },
    ],
  },
  {
    group: 'Operativo',
    items: [
      { href: '/?tab=dashboard', label: 'Inventory & CVE', legacy: true },
      { href: '/?tab=live',      label: 'Live Search',     legacy: true },
      { href: '/?tab=settings',  label: 'Impostazioni',    legacy: true },
    ],
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      aria-label="Navigazione principale"
      className="w-56 shrink-0 border-r border-gray-800 bg-gray-900 hidden lg:flex flex-col py-4 px-3 gap-4 sticky top-14 self-start max-h-[calc(100vh-3.5rem)] overflow-y-auto"
    >
      {NAV.map((section) => (
        <nav key={section.group} aria-label={section.group}>
          <h2 className="text-[10px] uppercase tracking-wide text-gray-600 font-semibold px-2 mb-1.5">
            {section.group}
          </h2>
          <ul className="flex flex-col gap-0.5">
            {section.items.map((item) => {
              const active = pathname === item.href.split('?')[0]
                && (item.href.split('?')[1] || '') === '';
              if (item.disabled) {
                return (
                  <li key={item.label}>
                    <span
                      className="flex items-center gap-2 px-2 py-1.5 text-xs text-gray-600 cursor-not-allowed"
                      title={item.hint || 'In arrivo'}
                    >
                      {item.badge && <span className="text-[10px] font-mono text-gray-700 bg-gray-800 border border-gray-700 px-1.5 rounded">{item.badge}</span>}
                      <span className="truncate">{item.label}</span>
                      <span className="ml-auto text-[10px] text-gray-700">soon</span>
                    </span>
                  </li>
                );
              }
              return (
                <li key={item.label}>
                  <Link
                    href={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={`flex items-center gap-2 px-2 py-1.5 rounded text-xs transition focus:outline-none ${
                      active
                        ? 'bg-indigo-600/30 text-white border border-indigo-700'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800/70 border border-transparent'
                    }`}
                  >
                    {item.badge && (
                      <span className="text-[10px] font-mono text-indigo-300 bg-indigo-900/40 border border-indigo-800 px-1.5 rounded">
                        {item.badge}
                      </span>
                    )}
                    <span className="truncate">{item.label}</span>
                    {item.legacy && (
                      <span className="ml-auto text-[10px] text-gray-700">legacy</span>
                    )}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
      ))}
    </aside>
  );
}
