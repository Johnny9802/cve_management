'use strict';

const {
  parseVersion,
  compareVersions,
  extractCpeVersion,
  parseCpeVendorProduct,
  isVersionInRange,
  isCveAffectingProduct,
} = require('../../src/services/version-matcher.service');

// ─── parseVersion ─────────────────────────────────────────────────────────────

describe('parseVersion', () => {
  test('standard semver returns numeric components', () => {
    const v = parseVersion('1.2.3');
    expect(v).toHaveLength(3);
    expect(v[0].n).toBe(1);
    expect(v[1].n).toBe(2);
    expect(v[2].n).toBe(3);
  });

  test('wildcard * returns null', () => {
    expect(parseVersion('*')).toBeNull();
  });

  test('empty string returns null', () => {
    expect(parseVersion('')).toBeNull();
  });

  test('null returns null', () => {
    expect(parseVersion(null)).toBeNull();
  });

  test('"n/a" returns null', () => {
    expect(parseVersion('n/a')).toBeNull();
  });

  test('OpenSSL patch letter: "1.0.2k" last component has patch=k', () => {
    const v = parseVersion('1.0.2k');
    expect(v[2].n).toBe(2);
    expect(v[2].patch).toBe('k');
  });

  test('pre-release "2.0-beta9" second component has pre=-beta9', () => {
    const v = parseVersion('2.0-beta9');
    expect(v[1].n).toBe(0);
    expect(v[1].pre).toBe('-beta9');
  });

  test('Windows build "10.0.19044.2006" parses four numeric components', () => {
    const v = parseVersion('10.0.19044.2006');
    expect(v).toHaveLength(4);
    expect(v[2].n).toBe(19044);
    expect(v[3].n).toBe(2006);
  });
});

// ─── compareVersions ──────────────────────────────────────────────────────────

describe('compareVersions', () => {
  // Basic ordering
  test('equal versions return 0', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });

  test('higher patch returns 1', () => {
    expect(compareVersions('1.2.4', '1.2.3')).toBe(1);
  });

  test('lower patch returns -1', () => {
    expect(compareVersions('1.2.3', '1.2.4')).toBe(-1);
  });

  test('higher minor returns 1', () => {
    expect(compareVersions('1.3.0', '1.2.9')).toBe(1);
  });

  test('higher major returns 1', () => {
    expect(compareVersions('2.0.0', '1.9.9')).toBe(1);
  });

  // Wildcard
  test('wildcard * vs anything returns 0 (undecidable)', () => {
    expect(compareVersions('*', '1.0')).toBe(0);
    expect(compareVersions('1.0', '*')).toBe(0);
  });

  // OpenSSL letter patches (1.0.2a < 1.0.2b < ... < 1.0.2k < ...)
  test('OpenSSL: 1.0.2k > 1.0.2j', () => {
    expect(compareVersions('1.0.2k', '1.0.2j')).toBe(1);
  });

  test('OpenSSL: 1.0.2a < 1.0.2k', () => {
    expect(compareVersions('1.0.2a', '1.0.2k')).toBe(-1);
  });

  test('OpenSSL: patch letter > base (1.0.2k > 1.0.2)', () => {
    expect(compareVersions('1.0.2k', '1.0.2')).toBe(1);
  });

  test('OpenSSL: base > pre-release (1.0.2 > 1.0.2-beta)', () => {
    // bare version is "base", hyphen is "pre" — base > pre
    expect(compareVersions('1.0.2', '1.0.2-beta')).toBe(1);
  });

  // Pre-release ordering
  test('pre-release < release: 2.0-beta9 < 2.0.0', () => {
    expect(compareVersions('2.0-beta9', '2.0.0')).toBe(-1);
  });

  test('release > pre-release: 2.0.0 > 2.0-beta9', () => {
    expect(compareVersions('2.0.0', '2.0-beta9')).toBe(1);
  });

  test('pre-release alpha < beta: 2.0-alpha < 2.0-beta9', () => {
    expect(compareVersions('2.0-alpha', '2.0-beta9')).toBe(-1);
  });

  test('earlier pre-release: 2.0-beta8 < 2.0-beta9', () => {
    expect(compareVersions('2.0-beta8', '2.0-beta9')).toBe(-1);
  });

  // Windows build numbers
  test('Windows: 10.0.19044 < 10.0.19045', () => {
    expect(compareVersions('10.0.19044', '10.0.19045')).toBe(-1);
  });

  test('Windows: 10.0.19044.2006 > 10.0.19044.1889', () => {
    expect(compareVersions('10.0.19044.2006', '10.0.19044.1889')).toBe(1);
  });

  // Length differences
  test('1.0 == 1.0.0 (shorter treated as .0 suffix)', () => {
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
  });

  test('1.1 > 1.0.9', () => {
    expect(compareVersions('1.1', '1.0.9')).toBe(1);
  });
});

// ─── extractCpeVersion ────────────────────────────────────────────────────────

describe('extractCpeVersion', () => {
  test('extracts version from valid CPE 2.3 string', () => {
    expect(extractCpeVersion('cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*')).toBe('3.0.1');
  });

  test('extracts wildcard version', () => {
    expect(extractCpeVersion('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*')).toBe('*');
  });

  test('returns null for null input', () => {
    expect(extractCpeVersion(null)).toBeNull();
  });

  test('returns null for short/invalid CPE', () => {
    expect(extractCpeVersion('cpe:2.3:a')).toBeNull();
  });
});

// ─── parseCpeVendorProduct ────────────────────────────────────────────────────

describe('parseCpeVendorProduct', () => {
  test('extracts vendor:product from CPE', () => {
    expect(parseCpeVendorProduct('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*')).toBe('apache:log4j');
  });

  test('extracts for OS CPE', () => {
    expect(parseCpeVendorProduct('cpe:2.3:o:microsoft:windows_10_22h2:10.0.19044:*:*:*:*:*:*:*')).toBe('microsoft:windows_10_22h2');
  });

  test('returns null for null', () => {
    expect(parseCpeVendorProduct(null)).toBeNull();
  });
});

// ─── isVersionInRange ─────────────────────────────────────────────────────────

describe('isVersionInRange', () => {
  // Exact CPE version (no range bounds)
  test('exact version match: installed == CPE version', () => {
    expect(isVersionInRange('3.0.1', {
      cpe: 'cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*',
    })).toBe(true);
  });

  test('exact version no match: installed != CPE version', () => {
    expect(isVersionInRange('3.0.2', {
      cpe: 'cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*',
    })).toBe(false);
  });

  test('wildcard CPE version (*) with no range bounds matches any version', () => {
    expect(isVersionInRange('99.99.99', {
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
    })).toBe(true);
  });

  // startIncluding
  test('startIncluding: installed >= start is in range', () => {
    expect(isVersionInRange('1.5.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
    })).toBe(true);
  });

  test('startIncluding: installed == start boundary is in range', () => {
    expect(isVersionInRange('1.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
    })).toBe(true);
  });

  test('startIncluding: installed < start is NOT in range', () => {
    expect(isVersionInRange('0.9.9', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
    })).toBe(false);
  });

  // startExcluding
  test('startExcluding: installed > start is in range', () => {
    expect(isVersionInRange('1.0.1', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartExcluding: '1.0.0',
    })).toBe(true);
  });

  test('startExcluding: installed == start boundary is NOT in range', () => {
    expect(isVersionInRange('1.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartExcluding: '1.0.0',
    })).toBe(false);
  });

  // endIncluding
  test('endIncluding: installed <= end is in range', () => {
    expect(isVersionInRange('2.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionEndIncluding: '2.0.0',
    })).toBe(true);
  });

  test('endIncluding: installed > end is NOT in range', () => {
    expect(isVersionInRange('2.0.1', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionEndIncluding: '2.0.0',
    })).toBe(false);
  });

  // endExcluding
  test('endExcluding: installed < end is in range', () => {
    expect(isVersionInRange('2.9.9', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionEndExcluding: '3.0.0',
    })).toBe(true);
  });

  test('endExcluding: installed == end boundary is NOT in range', () => {
    expect(isVersionInRange('3.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionEndExcluding: '3.0.0',
    })).toBe(false);
  });

  test('endExcluding: installed > end is NOT in range', () => {
    expect(isVersionInRange('3.0.1', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionEndExcluding: '3.0.0',
    })).toBe(false);
  });

  // Combined range (start + end)
  test('range [1.0, 3.0): 1.5 is in range', () => {
    expect(isVersionInRange('1.5.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
      versionEndExcluding: '3.0.0',
    })).toBe(true);
  });

  test('range [1.0, 3.0): 3.0 is NOT in range (exclusive upper)', () => {
    expect(isVersionInRange('3.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
      versionEndExcluding: '3.0.0',
    })).toBe(false);
  });

  test('range [1.0, 3.0]: 3.0 IS in range (inclusive upper)', () => {
    expect(isVersionInRange('3.0.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
      versionEndIncluding: '3.0.0',
    })).toBe(true);
  });

  // Legacy format (versionStart/versionEnd — no inclusive/exclusive info)
  test('legacy versionStart/versionEnd: 1.5 in range [1.0, 2.0]', () => {
    expect(isVersionInRange('1.5.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStart: '1.0.0',
      versionEnd: '2.0.0',
    })).toBe(true);
  });

  test('legacy versionStart/versionEnd: 2.1 NOT in range [1.0, 2.0]', () => {
    expect(isVersionInRange('2.1.0', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStart: '1.0.0',
      versionEnd: '2.0.0',
    })).toBe(false);
  });

  // OpenSSL letter patches within a range
  test('OpenSSL: 1.0.2k in range [1.0.2a, 1.0.2l)', () => {
    expect(isVersionInRange('1.0.2k', {
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.2a',
      versionEndExcluding: '1.0.2l',
    })).toBe(true);
  });

  test('OpenSSL: 1.0.2m NOT in range [1.0.2a, 1.0.2l)', () => {
    expect(isVersionInRange('1.0.2m', {
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.2a',
      versionEndExcluding: '1.0.2l',
    })).toBe(false);
  });

  // Pre-release lower bound
  test('log4j: 2.14.1 in range [2.0-beta9, 2.14.1]', () => {
    expect(isVersionInRange('2.14.1', {
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    })).toBe(true);
  });

  test('log4j: 2.15.0 NOT in range [2.0-beta9, 2.14.1]', () => {
    expect(isVersionInRange('2.15.0', {
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    })).toBe(false);
  });

  test('log4j: 2.0.0 in range [2.0-beta9, 2.14.1]', () => {
    // 2.0.0 (release) > 2.0-beta9 (pre-release) → satisfies lower bound
    expect(isVersionInRange('2.0.0', {
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    })).toBe(true);
  });

  // Wildcard installed version
  test('wildcard installed version (*) matches any range', () => {
    expect(isVersionInRange('*', {
      cpe: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.0',
      versionEndExcluding: '2.0.0',
    })).toBe(true);
  });
});

// ─── isCveAffectingProduct ────────────────────────────────────────────────────

describe('isCveAffectingProduct', () => {
  // No CPE data — include conservatively
  test('no affected_cpe: uncertain inclusion', () => {
    const result = isCveAffectingProduct(
      { name: 'OpenSSL', version: '3.0.1', vendor: '', cpe_keyword: '' },
      []
    );
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('uncertain');
  });

  test('null affected_cpe: uncertain inclusion', () => {
    const result = isCveAffectingProduct(
      { name: 'OpenSSL', version: '3.0.1', vendor: '', cpe_keyword: '' },
      null
    );
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('uncertain');
  });

  // ── Product with CPE keyword ──

  test('CPE keyword: version in range → certain match', () => {
    const product = {
      name: 'OpenSSL',
      version: '3.0.1',
      vendor: 'OpenSSL',
      cpe_keyword: 'cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '3.0.0',
      versionEndExcluding: '3.0.7',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('CPE keyword: version above range → certain no-match', () => {
    const product = {
      name: 'OpenSSL',
      version: '3.0.7',
      vendor: 'OpenSSL',
      cpe_keyword: 'cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '3.0.0',
      versionEndExcluding: '3.0.7',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  test('CPE keyword: version below range → certain no-match', () => {
    const product = {
      name: 'OpenSSL',
      version: '2.9.0',
      vendor: '',
      cpe_keyword: 'cpe:2.3:a:openssl:openssl:2.9.0:*:*:*:*:*:*:*',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '3.0.0',
      versionEndExcluding: '3.0.7',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  // ── Product without CPE keyword (name-based matching) ──

  test('name match: OpenSSL 3.0.1 in range [3.0.0, 3.0.7) → certain match', () => {
    const product = {
      name: 'OpenSSL',
      version: '3.0.1',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '3.0.0',
      versionEndExcluding: '3.0.7',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('name match: nginx 1.18.0 in range [*, 1.20.1) → certain match', () => {
    const product = {
      name: 'nginx',
      version: '1.18.0',
      vendor: 'nginx',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
      versionEndExcluding: '1.20.1',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('name match: nginx 1.22.0 NOT in range [*, 1.20.1) → certain no-match', () => {
    const product = {
      name: 'nginx',
      version: '1.22.0',
      vendor: 'nginx',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
      versionEndExcluding: '1.20.1',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  // ── Log4j / CVE-2021-44228 scenario ──

  test('log4j 2.14.1 in Log4Shell range → certain match', () => {
    const product = {
      name: 'Apache Log4j',
      version: '2.14.1',
      vendor: 'Apache',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('log4j 2.15.0 NOT in Log4Shell range → certain no-match', () => {
    const product = {
      name: 'Apache Log4j',
      version: '2.15.0',
      vendor: 'Apache',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  test('log4j 2.16.0 (CVE-2021-45046 patch) NOT in Log4Shell range → certain no-match', () => {
    const product = {
      name: 'log4j',
      version: '2.16.0',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      versionStartIncluding: '2.0-beta9',
      versionEndIncluding: '2.14.1',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  // ── OpenSSL letter-patch versions ──

  test('OpenSSL 1.0.2k in range [1.0.2a, 1.0.2l) → certain match', () => {
    const product = {
      name: 'OpenSSL',
      version: '1.0.2k',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.2a',
      versionEndExcluding: '1.0.2l',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('OpenSSL 1.0.2m NOT in range [1.0.2a, 1.0.2l) → certain no-match', () => {
    const product = {
      name: 'OpenSSL',
      version: '1.0.2m',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      versionStartIncluding: '1.0.2a',
      versionEndExcluding: '1.0.2l',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  // ── No matching CPE vendor:product ──

  test('CVE for unrelated product → uncertain inclusion (no false negative)', () => {
    const product = {
      name: 'nginx',
      version: '1.18.0',
      vendor: 'nginx',
      cpe_keyword: '',
    };
    // These CPE entries are for Apache httpd, not nginx
    const affectedCpes = [{
      cpe: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
      versionEndExcluding: '2.4.51',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('uncertain');
  });

  // ── Multiple CPE entries — match on any ──

  test('matches second CPE entry when first does not apply', () => {
    const product = {
      name: 'OpenSSL',
      version: '1.1.1k',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [
      {
        cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
        versionStartIncluding: '3.0.0',
        versionEndExcluding: '3.0.7',
      },
      {
        cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
        versionStartIncluding: '1.1.1',
        versionEndExcluding: '1.1.1n',
      },
    ];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('version above all CPE ranges → certain no-match', () => {
    const product = {
      name: 'OpenSSL',
      version: '3.1.0',
      vendor: '',
      cpe_keyword: '',
    };
    const affectedCpes = [
      {
        cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
        versionStartIncluding: '3.0.0',
        versionEndExcluding: '3.0.7',
      },
      {
        cpe: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
        versionStartIncluding: '1.1.1',
        versionEndExcluding: '1.1.1n',
      },
    ];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });

  // ── Windows CPE keyword ──

  test('Windows 10 22H2 CPE keyword: version matches OS CPE', () => {
    const product = {
      name: 'Windows 10',
      version: '10.0.19044',
      vendor: 'Microsoft',
      cpe_keyword: 'cpe:2.3:o:microsoft:windows_10_22h2:10.0.19044:*:*:*:*:*:*:*',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*',
      versionEndExcluding: '10.0.19044.3086',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(true);
    expect(result.confidence).toBe('certain');
  });

  test('Windows 10 22H2: patched version is NOT in range', () => {
    const product = {
      name: 'Windows 10',
      version: '10.0.19044.3086',
      vendor: 'Microsoft',
      cpe_keyword: 'cpe:2.3:o:microsoft:windows_10_22h2:10.0.19044.3086:*:*:*:*:*:*:*',
    };
    const affectedCpes = [{
      cpe: 'cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*',
      versionEndExcluding: '10.0.19044.3086',
    }];
    const result = isCveAffectingProduct(product, affectedCpes);
    expect(result.affected).toBe(false);
    expect(result.confidence).toBe('certain');
  });
});
