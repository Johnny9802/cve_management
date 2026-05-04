'use client';

/**
 * Per-owner table for the Remediation dashboard.
 *
 * Highlights breached counts in red; clicking the row navigates to the
 * Triage dashboard pre-filtered by that owner (Sprint 3 will add
 * `?owner=…` to the URL state).
 */
export default function OwnerWorkloadTable({ owners = [], loading }) {
  if (loading && owners.length === 0) {
    return (
      <Section title="Carico per owner">
        <div className="text-xs text-gray-500 text-center py-4">Caricamento…</div>
      </Section>
    );
  }
  if (!owners.length) {
    return (
      <Section title="Carico per owner">
        <div className="text-xs text-gray-500 text-center py-4 italic">
          Nessun finding ancora assegnato.
        </div>
      </Section>
    );
  }

  return (
    <Section title="Carico per owner" subtitle="Apertura · in review · breach · MTTR">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500">
              <th className="text-left px-3 py-1.5 font-medium">Owner</th>
              <th className="text-right px-2 py-1.5 font-medium">Open</th>
              <th className="text-right px-2 py-1.5 font-medium">In review</th>
              <th className="text-right px-2 py-1.5 font-medium">Planned</th>
              <th className="text-right px-2 py-1.5 font-medium">Risk acc.</th>
              <th className="text-right px-2 py-1.5 font-medium">Remed.</th>
              <th className="text-right px-2 py-1.5 font-medium">Breached</th>
              <th className="text-right px-2 py-1.5 font-medium">MTTR (gg)</th>
              <th className="text-right px-2 py-1.5 font-medium">Totale</th>
            </tr>
          </thead>
          <tbody>
            {owners.map((o) => (
              <tr key={o.owner} className="border-t border-gray-800">
                <td className="px-3 py-1.5 text-gray-200 font-medium truncate max-w-[200px]">
                  {o.owner === 'unassigned' ? (
                    <span className="text-gray-500 italic">unassigned</span>
                  ) : o.owner}
                </td>
                <td className="px-2 py-1.5 text-right font-mono text-gray-300">{o.open_count}</td>
                <td className="px-2 py-1.5 text-right font-mono text-gray-300">{o.in_review_count}</td>
                <td className="px-2 py-1.5 text-right font-mono text-gray-300">{o.planned_count}</td>
                <td className="px-2 py-1.5 text-right font-mono text-yellow-300">{o.accepted_risk_count}</td>
                <td className="px-2 py-1.5 text-right font-mono text-green-300">{o.remediated_count}</td>
                <td className={`px-2 py-1.5 text-right font-mono ${o.breached_count > 0 ? 'text-red-300' : 'text-gray-500'}`}>
                  {o.breached_count}
                </td>
                <td className="px-2 py-1.5 text-right font-mono text-gray-300">
                  {o.avg_days_to_remediate ?? '—'}
                </td>
                <td className="px-2 py-1.5 text-right font-mono text-gray-200">{o.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

function Section({ title, subtitle, children }) {
  return (
    <section
      aria-label={title}
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
    >
      <header className="px-4 py-2.5 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}
