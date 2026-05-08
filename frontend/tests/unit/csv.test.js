import { describe, it, expect } from 'vitest';
import { parseCsv, splitCsvLine } from '../../src/lib/csv';

describe('csv parser', () => {
  it('skips a header row when one of the hint tokens appears', () => {
    const { rows, errors } = parseCsv('name,version,vendor\nnginx,1.18.0,nginx\n');
    expect(errors).toEqual([]);
    expect(rows).toEqual([
      { name: 'nginx', version: '1.18.0', vendor: 'nginx', cpe_keyword: undefined },
    ]);
  });

  it('parses without header', () => {
    const { rows } = parseCsv('nginx,1.18.0\nopenssl,3.0.1');
    expect(rows.length).toBe(2);
    expect(rows[0]).toMatchObject({ name: 'nginx', version: '1.18.0' });
  });

  it('reports rows with missing name or version', () => {
    const { rows, errors } = parseCsv(',1.0\nnginx,\nokp,2.0');
    expect(rows.length).toBe(1);  // only "okp,2.0"
    expect(errors).toHaveLength(2);
  });

  it('splitCsvLine honors quoted fields', () => {
    const out = splitCsvLine('"a,b",c,"d ""e"" f"');
    expect(out).toEqual(['a,b', 'c', 'd e f']);
  });

  it('trims surrounding whitespace', () => {
    const { rows } = parseCsv('  nginx ,  1.18.0  ');
    expect(rows[0]).toMatchObject({ name: 'nginx', version: '1.18.0' });
  });
});
