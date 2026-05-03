'use strict';

/**
 * Version Range Matcher
 *
 * Evaluates whether an installed product version falls within the affected
 * version ranges stored in NVD's CPE configurations (affected_cpe field).
 *
 * WHY THIS EXISTS:
 * NVD keyword search returns all CVEs mentioning a product name regardless of
 * which version is affected. Without this check, "OpenSSL 1.1.1k" matches every
 * OpenSSL CVE ever published. This service uses the structured CPE version-range
 * data that NVD stores per CVE to make a precise determination.
 *
 * VERSION STRING CONVENTIONS HANDLED:
 *   Standard semver : 1.2.3, 1.2.3.4
 *   OpenSSL patches : 1.0.2k  (letter suffix = patch level, 2k > 2j > 2a > 2)
 *   Pre-releases    : 2.0-beta9, 2.0-rc1  (always < the release: 2.0-beta9 < 2.0.0)
 *   Windows builds  : 10.0.19044.2006
 *   Wildcards       : *  (any version — always matches)
 *
 * CONFIDENCE LEVELS:
 *   'certain'   - CPE vendor:product matched; version range evaluated precisely
 *   'uncertain' - could not match CPE vendor:product, or no CPE data at all
 *                 → CVE is INCLUDED conservatively to avoid false negatives
 */

// ─── Version parsing ──────────────────────────────────────────────────────────

/**
 * Parses one dot-separated component of a version string.
 * Returns { n, pre, patch } where:
 *   n     - leading integer
 *   pre   - pre-release suffix (starts with '-', e.g. '-beta9') or null
 *   patch - patch-letter suffix (no hyphen, e.g. 'k' from '2k') or null
 *
 * Sort order for the same n: pre-release < base < patch-letter
 *   e.g.  2-beta9  <  2  <  2k  <  2z
 */
function parseComponent(part) {
  const p = (part || '').toLowerCase().trim();

  // Numeric + hyphen pre-release: "0-beta9", "3-rc1", "1-alpha"
  const pre = p.match(/^(\d+)(-[a-z].*)$/);
  if (pre) return { n: parseInt(pre[1], 10), pre: pre[2], patch: null };

  // Numeric + patch letters: "2k", "2a", "19044"
  const patch = p.match(/^(\d+)([a-z]+\d*)$/);
  if (patch) return { n: parseInt(patch[1], 10), pre: null, patch: patch[2] };

  // Pure integer
  const num = parseInt(p, 10);
  if (!isNaN(num)) return { n: num, pre: null, patch: null };

  // Non-numeric fallback (e.g. "beta", "rc1" without leading digits)
  return { n: 0, pre: `-${p}`, patch: null };
}

/**
 * Parses a full version string into an array of components.
 * Returns null for wildcards or empty/unresolvable strings.
 */
function parseVersion(vStr) {
  if (!vStr) return null;
  const s = vStr.trim().toLowerCase();
  if (s === '*' || s === '-' || s === '' || s === 'n/a' || s === 'none') return null;
  return s.split('.').map(parseComponent);
}

/**
 * Compares two parsed components.
 * Returns -1, 0, or 1.
 */
function compareComponents(ca, cb) {
  if (ca.n !== cb.n) return ca.n > cb.n ? 1 : -1;

  // Same base number — sort by type: pre < base < patch
  const typeOrder = (c) => (c.pre !== null ? 0 : c.patch !== null ? 2 : 1);
  const ta = typeOrder(ca);
  const tb = typeOrder(cb);
  if (ta !== tb) return ta > tb ? 1 : -1;

  // Same type — compare suffix lexicographically
  const sa = ca.pre || ca.patch || '';
  const sb = cb.pre || cb.patch || '';
  if (sa === sb) return 0;
  return sa > sb ? 1 : -1;
}

/**
 * Compares two version strings.
 * Returns -1 if a < b, 0 if a == b, 1 if a > b.
 * Returns 0 when either is a wildcard (cannot determine ordering).
 */
function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return 0; // wildcard or unparseable

  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const ca = pa[i] || { n: 0, pre: null, patch: null };
    const cb = pb[i] || { n: 0, pre: null, patch: null };
    const cmp = compareComponents(ca, cb);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

// ─── CPE string utilities ─────────────────────────────────────────────────────

/**
 * Extracts the version component (position 5) from a CPE 2.3 URI.
 * cpe:2.3:TYPE:VENDOR:PRODUCT:VERSION:...
 */
function extractCpeVersion(cpeStr) {
  if (!cpeStr) return null;
  const parts = cpeStr.split(':');
  return parts.length >= 6 ? parts[5] : null;
}

/**
 * Extracts the "vendor:product" pair from a CPE 2.3 URI.
 */
function parseCpeVendorProduct(cpeStr) {
  if (!cpeStr) return null;
  const parts = cpeStr.split(':');
  if (parts.length < 5) return null;
  return `${parts[3]}:${parts[4]}`;
}

/**
 * Normalises a free-form string to a CPE-style slug.
 * "Apache Log4j" → "apache_log4j"
 */
function normaliseSlug(str) {
  return (str || '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_.-]/g, '');
}

// ─── Version range evaluation ─────────────────────────────────────────────────

/**
 * Determines whether installedVersion falls within the version range described
 * by a single CPE match entry.
 *
 * Accepts both the new format:
 *   { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding }
 * and the legacy format stored before this fix:
 *   { versionStart, versionEnd }  (treated as inclusive on both ends)
 *
 * Returns true when the version is within range, false otherwise.
 */
function isVersionInRange(installedVersion, cpeEntry) {
  const installed = (installedVersion || '').trim();
  if (!installed || installed === '*') return true; // cannot determine

  const {
    versionStartIncluding,
    versionStartExcluding,
    versionEndIncluding,
    versionEndExcluding,
    // Legacy fallback (data stored before this fix was applied)
    versionStart,
    versionEnd,
  } = cpeEntry;

  const startInc = versionStartIncluding || versionStart || null;
  const startExc = versionStartExcluding || null;
  const endInc   = versionEndIncluding   || null;
  const endExc   = versionEndExcluding   || versionEnd   || null;

  // No range bounds → check CPE version field for exact match
  if (!startInc && !startExc && !endInc && !endExc) {
    const cpeVer = extractCpeVersion(cpeEntry.cpe);
    if (!cpeVer || cpeVer === '*' || cpeVer === '-') return true; // any version
    return compareVersions(installed, cpeVer) === 0;
  }

  // Lower bound
  if (startInc && compareVersions(installed, startInc) < 0)  return false;
  if (startExc && compareVersions(installed, startExc) <= 0) return false;

  // Upper bound
  if (endInc && compareVersions(installed, endInc) > 0)   return false;
  if (endExc && compareVersions(installed, endExc) >= 0)  return false;

  return true;
}

// ─── Product ↔ CVE matching ───────────────────────────────────────────────────

/**
 * Decides whether a CPE entry (one element of affected_cpe) belongs to the
 * same vendor:product as the given product record.
 *
 * Strategy (in order):
 * 1. If the product has a full CPE keyword, compare vendor:product directly.
 * 2. Otherwise normalise name/vendor and try substring matching.
 */
function productMatchesCpeVendorProduct(product, cpeStr) {
  const cpeVP = parseCpeVendorProduct(cpeStr);
  if (!cpeVP) return false;
  const [cpeVendor, cpeProd] = cpeVP.split(':');

  // ── Strategy 1: direct CPE comparison ──
  if (product.cpe_keyword && product.cpe_keyword.toLowerCase().startsWith('cpe:')) {
    const productVP = parseCpeVendorProduct(product.cpe_keyword);
    if (productVP) {
      const [pVendor, pProd] = productVP.split(':');
      return pVendor === cpeVendor && pProd === cpeProd;
    }
  }

  // ── Strategy 2: name/vendor slug matching ──
  const normName   = normaliseSlug(product.name);
  const normVendor = normaliseSlug(product.vendor);

  // Product name must relate to the CPE product slug
  const nameMatches =
    normName === cpeProd ||
    normName.includes(cpeProd) ||
    cpeProd.includes(normName);

  if (!nameMatches) return false;

  // If vendor is provided, it must relate to the CPE vendor
  if (normVendor) {
    return (
      normVendor === cpeVendor ||
      normVendor.includes(cpeVendor) ||
      cpeVendor.includes(normVendor)
    );
  }

  return true; // no vendor to contradict the match
}

/**
 * Determines whether a CVE affects a specific product+version combination.
 *
 * @param {object} product  - { name, version, vendor, cpe_keyword }
 * @param {Array}  affectedCpes - array from cve.affected_cpe (NVD configuration data)
 *
 * @returns {{ affected: boolean, confidence: 'certain'|'uncertain', reason: string }}
 *
 * confidence='certain'   → positive evidence used (CPE matched, version in range)
 * confidence='uncertain' → no CPE data or product not in any CPE → included conservatively
 */
function isCveAffectingProduct(product, affectedCpes) {
  if (!Array.isArray(affectedCpes) || affectedCpes.length === 0) {
    return {
      affected: true,
      confidence: 'uncertain',
      reason: 'no_cpe_data',
    };
  }

  const installedVersion = (product.version || '').trim();
  let productCpeMatchFound = false;

  for (const cpeEntry of affectedCpes) {
    const cpeName = cpeEntry.cpe || '';

    if (!productMatchesCpeVendorProduct(product, cpeName)) continue;
    productCpeMatchFound = true;

    if (isVersionInRange(installedVersion, cpeEntry)) {
      return {
        affected: true,
        confidence: 'certain',
        reason: `version_in_range:${cpeName}`,
      };
    }
  }

  if (productCpeMatchFound) {
    return {
      affected: false,
      confidence: 'certain',
      reason: `version_outside_all_ranges:${installedVersion}`,
    };
  }

  // No CPE entry matched this product at all — include conservatively
  return {
    affected: true,
    confidence: 'uncertain',
    reason: 'no_cpe_vendor_product_match',
  };
}

module.exports = {
  parseVersion,
  compareVersions,
  extractCpeVersion,
  parseCpeVendorProduct,
  isVersionInRange,
  isCveAffectingProduct,
};
