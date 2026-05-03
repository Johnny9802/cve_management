'use strict';

const { parseNvdCve } = require('../../src/services/nvd.service');

// Minimal NVD CVE object factory so tests only declare what they care about
function makeCve(overrides = {}) {
  return {
    id: 'CVE-2021-44228',
    descriptions: [{ lang: 'en', value: 'Log4Shell RCE' }],
    published: '2021-12-10T00:00:00.000',
    lastModified: '2021-12-12T00:00:00.000',
    metrics: {},
    references: [],
    weaknesses: [],
    configurations: [],
    ...overrides,
  };
}

describe('parseNvdCve', () => {
  test('null input returns null', () => {
    expect(parseNvdCve(null)).toBeNull();
  });

  test('missing id returns null', () => {
    expect(parseNvdCve({ descriptions: [] })).toBeNull();
  });

  test('parses basic fields', () => {
    const result = parseNvdCve(makeCve());
    expect(result.cve_id).toBe('CVE-2021-44228');
    expect(result.description).toBe('Log4Shell RCE');
    expect(result.published_at).toBe('2021-12-10T00:00:00.000');
    expect(result.last_modified_at).toBe('2021-12-12T00:00:00.000');
  });

  test('picks English description when multiple languages present', () => {
    const result = parseNvdCve(makeCve({
      descriptions: [
        { lang: 'es', value: 'Descripción en español' },
        { lang: 'en', value: 'English description' },
      ],
    }));
    expect(result.description).toBe('English description');
  });

  test('falls back to empty string when no English description', () => {
    const result = parseNvdCve(makeCve({
      descriptions: [{ lang: 'zh', value: '中文' }],
    }));
    expect(result.description).toBe('');
  });

  // CVSS v3.1
  test('parses CVSS v3.1 score and vector', () => {
    const result = parseNvdCve(makeCve({
      metrics: {
        cvssMetricV31: [{
          cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
        }],
      },
    }));
    expect(result.cvss_v3_score).toBe(10.0);
    expect(result.severity).toBe('CRITICAL');
    expect(result.cvss_v3_vector).toContain('CVSS:3.1');
  });

  // CVSS v3.0 fallback when no v3.1
  test('falls back to CVSS v3.0 when v3.1 absent', () => {
    const result = parseNvdCve(makeCve({
      metrics: {
        cvssMetricV30: [{
          cvssData: { baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.0/AV:N' },
        }],
      },
    }));
    expect(result.cvss_v3_score).toBe(7.5);
    expect(result.severity).toBe('HIGH');
  });

  // CVSS v2 fallback
  test('falls back to CVSS v2 severity when no v3 present', () => {
    const result = parseNvdCve(makeCve({
      metrics: {
        cvssMetricV2: [{
          cvssData: { baseScore: 5.0 },
          baseSeverity: 'MEDIUM',
        }],
      },
    }));
    expect(result.cvss_v2_score).toBe(5.0);
    expect(result.severity).toBe('MEDIUM');
  });

  // No metrics at all
  test('returns null scores when no metrics present', () => {
    const result = parseNvdCve(makeCve({ metrics: {} }));
    expect(result.cvss_v3_score).toBeNull();
    expect(result.cvss_v2_score).toBeNull();
    expect(result.severity).toBe('NONE');
  });

  // Severity normalisation
  test('severity is always uppercase', () => {
    const result = parseNvdCve(makeCve({
      metrics: {
        cvssMetricV31: [{
          cvssData: { baseScore: 9.8, baseSeverity: 'critical', vectorString: '' },
        }],
      },
    }));
    expect(result.severity).toBe('CRITICAL');
  });

  // References
  test('parses references with tags', () => {
    const result = parseNvdCve(makeCve({
      references: [
        { url: 'https://example.com/advisory', tags: ['Vendor Advisory'] },
        { url: 'https://nvd.nist.gov', tags: [] },
      ],
    }));
    expect(result.references).toHaveLength(2);
    expect(result.references[0].url).toBe('https://example.com/advisory');
    expect(result.references[0].tags).toContain('Vendor Advisory');
  });

  // Weaknesses (CWE)
  test('parses weaknesses flat list', () => {
    const result = parseNvdCve(makeCve({
      weaknesses: [
        { description: [{ value: 'CWE-502' }, { value: 'CWE-917' }] },
      ],
    }));
    expect(result.weaknesses).toContain('CWE-502');
    expect(result.weaknesses).toContain('CWE-917');
  });

  // CPE configurations — new format with inclusive/exclusive preserved
  test('extracts affected CPE ranges with inclusive/exclusive fields', () => {
    const result = parseNvdCve(makeCve({
      configurations: [{
        nodes: [{
          cpeMatch: [{
            vulnerable: true,
            criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
            versionStartIncluding: '2.0-beta9',
            versionEndIncluding: '2.14.1',
          }],
        }],
      }],
    }));
    expect(result.affected_cpe).toHaveLength(1);
    const cpe = result.affected_cpe[0];
    expect(cpe.cpe).toBe('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*');
    expect(cpe.versionStartIncluding).toBe('2.0-beta9');
    expect(cpe.versionEndIncluding).toBe('2.14.1');
    // Exclusive fields should be null, not the inclusive values
    expect(cpe.versionStartExcluding).toBeNull();
    expect(cpe.versionEndExcluding).toBeNull();
  });

  test('non-vulnerable CPE entries are not included in affected_cpe', () => {
    const result = parseNvdCve(makeCve({
      configurations: [{
        nodes: [{
          cpeMatch: [
            { vulnerable: true,  criteria: 'cpe:2.3:a:apache:log4j:2.14.1:*', versionEndExcluding: '2.15.0' },
            { vulnerable: false, criteria: 'cpe:2.3:o:linux:linux_kernel:*' },
          ],
        }],
      }],
    }));
    expect(result.affected_cpe).toHaveLength(1);
    expect(result.affected_cpe[0].cpe).toContain('log4j');
  });

  test('nested children nodes are included', () => {
    const result = parseNvdCve(makeCve({
      configurations: [{
        nodes: [{
          cpeMatch: [],
          children: [{
            cpeMatch: [{
              vulnerable: true,
              criteria: 'cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*',
              versionEndExcluding: '3.0.7',
            }],
          }],
        }],
      }],
    }));
    expect(result.affected_cpe).toHaveLength(1);
    expect(result.affected_cpe[0].cpe).toContain('openssl');
  });

  // CISA KEV fields from NVD
  test('sets in_cisa_kev=true when cisaExploitAdd present', () => {
    const result = parseNvdCve(makeCve({ cisaExploitAdd: '2021-12-10', cisaActionDue: '2021-12-24' }));
    expect(result.in_cisa_kev).toBe(true);
    expect(result.cisa_kev_date_added).toBe('2021-12-10');
    expect(result.cisa_kev_due_date).toBe('2021-12-24');
  });

  test('sets in_cisa_kev=false when cisaExploitAdd absent', () => {
    const result = parseNvdCve(makeCve());
    expect(result.in_cisa_kev).toBe(false);
    expect(result.cisa_kev_date_added).toBeNull();
  });
});
