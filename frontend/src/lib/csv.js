/**
 * Lightweight CSV parser for inventory upload (Sprint 2 — S2.4).
 *
 * Extracted from AddProductModal so the new /inventory page can reuse
 * the same logic. Handles quoted fields and a header row when one of
 * the common header names is detected (name / nome / product).
 *
 * Returns ``{ rows, errors }`` where each error is a soft warning
 * (e.g. "row 4: missing version") so the UI can preview valid rows
 * and surface skipped ones to the user.
 */

const HEADER_HINTS = ['nome', 'name', 'product'];

export function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (!lines.length) return { rows: [], errors: [] };

  const startIdx = HEADER_HINTS.some((h) => lines[0].toLowerCase().includes(h)) ? 1 : 0;

  const rows = [];
  const errors = [];
  for (let i = startIdx; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    const name = (cols[0] ?? '').trim();
    const version = (cols[1] ?? '').trim();
    if (!name || !version) {
      errors.push(`riga ${i + 1}: nome o versione mancante`);
      continue;
    }
    rows.push({
      name,
      version,
      vendor: (cols[2] ?? '').trim() || undefined,
      cpe_keyword: (cols[3] ?? '').trim() || undefined,
    });
  }
  return { rows, errors };
}

export function splitCsvLine(line) {
  const out = [];
  let current = '';
  let inQuotes = false;
  for (const ch of line) {
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (ch === ',' && !inQuotes) { out.push(current); current = ''; continue; }
    current += ch;
  }
  out.push(current);
  return out;
}
