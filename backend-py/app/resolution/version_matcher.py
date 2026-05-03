"""Version range matcher — Python port of version-matcher.service.js.

Determines whether an installed product version falls within the affected
version ranges stored in NVD CPE configurations.

See the original JS source for detailed rationale comments (backend/src/services/version-matcher.service.js).

Confidence levels:
  CERTAIN   — CPE vendor:product matched; version evaluated against explicit ranges
  UNCERTAIN — no CPE data, or product not found in any CPE entry
              → CVE is INCLUDED conservatively to avoid false negatives
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


# ─── Version component ───────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class VersionComponent:
    n: int
    pre: str | None    # "-beta9", "-rc1"  → sorts BELOW base
    patch: str | None  # "k", "z"          → sorts ABOVE base


def _parse_component(part: str) -> VersionComponent:
    p = (part or "").lower().strip()

    # "0-beta9", "3-rc1"
    m = re.match(r"^(\d+)(-[a-z].*)$", p)
    if m:
        return VersionComponent(n=int(m.group(1)), pre=m.group(2), patch=None)

    # "2k", "2a", "2z" (OpenSSL patch letter)
    m = re.match(r"^(\d+)([a-z]+\d*)$", p)
    if m:
        return VersionComponent(n=int(m.group(1)), pre=None, patch=m.group(2))

    # Pure integer
    try:
        return VersionComponent(n=int(p), pre=None, patch=None)
    except ValueError:
        pass

    # Non-numeric fallback ("beta", "rc1" without leading digits)
    return VersionComponent(n=0, pre=f"-{p}", patch=None)


def _parse_version(v_str: str) -> list[VersionComponent] | None:
    if not v_str:
        return None
    s = v_str.strip().lower()
    if s in ("*", "-", "", "n/a", "none"):
        return None
    return [_parse_component(part) for part in s.split(".")]


def _compare_components(ca: VersionComponent, cb: VersionComponent) -> int:
    if ca.n != cb.n:
        return 1 if ca.n > cb.n else -1

    # pre < base < patch
    def _type(c: VersionComponent) -> int:
        return 0 if c.pre is not None else (2 if c.patch is not None else 1)

    ta, tb = _type(ca), _type(cb)
    if ta != tb:
        return 1 if ta > tb else -1

    sa = ca.pre or ca.patch or ""
    sb = cb.pre or cb.patch or ""
    if sa == sb:
        return 0
    return 1 if sa > sb else -1


def compare_versions(a: str, b: str) -> int:
    """Return -1 | 0 | 1. Returns 0 when either is a wildcard."""
    pa, pb = _parse_version(a), _parse_version(b)
    if pa is None or pb is None:
        return 0  # wildcard → cannot determine ordering

    length = max(len(pa), len(pb))
    _zero = VersionComponent(n=0, pre=None, patch=None)
    for i in range(length):
        ca = pa[i] if i < len(pa) else _zero
        cb = pb[i] if i < len(pb) else _zero
        cmp = _compare_components(ca, cb)
        if cmp != 0:
            return cmp
    return 0


# ─── CPE string utilities ─────────────────────────────────────────────────────

def extract_cpe_version(cpe_str: str) -> str | None:
    """Extract position-5 version field from a CPE 2.3 URI."""
    if not cpe_str:
        return None
    parts = cpe_str.split(":")
    return parts[5] if len(parts) >= 6 else None


def parse_cpe_vendor_product(cpe_str: str) -> str | None:
    """Return 'vendor:product' from a CPE 2.3 URI."""
    if not cpe_str:
        return None
    parts = cpe_str.split(":")
    if len(parts) < 5:
        return None
    return f"{parts[3]}:{parts[4]}"


def normalise_slug(s: str) -> str:
    """'Apache Log4j' → 'apache_log4j'"""
    return re.sub(r"[^a-z0-9_.\-]", "", (s or "").lower().strip().replace(" ", "_"))


# ─── Version range evaluation ─────────────────────────────────────────────────

def is_version_in_range(installed_version: str, cpe_entry: dict[str, Any]) -> bool:
    """True when installed_version falls within the CPE entry's version range.

    Handles both NVD 2.0 format (versionStartIncluding/Excluding, versionEndIncluding/Excluding)
    and the legacy format (versionStart, versionEnd).
    """
    installed = (installed_version or "").strip()
    if not installed or installed == "*":
        return True  # unknown version → cannot disprove

    start_inc = cpe_entry.get("versionStartIncluding") or cpe_entry.get("versionStart") or None
    start_exc = cpe_entry.get("versionStartExcluding") or None
    end_inc   = cpe_entry.get("versionEndIncluding") or None
    end_exc   = cpe_entry.get("versionEndExcluding") or cpe_entry.get("versionEnd") or None

    if not any((start_inc, start_exc, end_inc, end_exc)):
        # No range — check the CPE version field for an exact match
        cpe_ver = extract_cpe_version(cpe_entry.get("criteria") or cpe_entry.get("cpe", ""))
        if not cpe_ver or cpe_ver in ("*", "-"):
            return True
        return compare_versions(installed, cpe_ver) == 0

    if start_inc and compare_versions(installed, start_inc) < 0:
        return False
    if start_exc and compare_versions(installed, start_exc) <= 0:
        return False
    if end_inc and compare_versions(installed, end_inc) > 0:
        return False
    if end_exc and compare_versions(installed, end_exc) >= 0:
        return False

    return True


# ─── Product ↔ CVE matching ───────────────────────────────────────────────────

def _product_matches_cpe_vendor_product(product: dict[str, Any], cpe_str: str) -> bool:
    cpe_vp = parse_cpe_vendor_product(cpe_str)
    if not cpe_vp:
        return False
    cpe_vendor, cpe_prod = cpe_vp.split(":")

    # Strategy 1: direct CPE comparison (product has a full CPE keyword)
    keyword = (product.get("cpe_keyword") or product.get("normalized_cpe") or "").lower()
    if keyword.startswith("cpe:"):
        product_vp = parse_cpe_vendor_product(keyword)
        if product_vp:
            p_vendor, p_prod = product_vp.split(":")
            return p_vendor == cpe_vendor and p_prod == cpe_prod

    # Strategy 2: name/vendor slug substring matching
    norm_name   = normalise_slug(product.get("name") or "")
    norm_vendor = normalise_slug(product.get("vendor") or "")

    name_matches = (
        norm_name == cpe_prod
        or norm_name in cpe_prod
        or cpe_prod in norm_name
    )
    if not name_matches:
        return False

    if norm_vendor:
        return (
            norm_vendor == cpe_vendor
            or norm_vendor in cpe_vendor
            or cpe_vendor in norm_vendor
        )
    return True


class Confidence(str, Enum):
    CERTAIN = "certain"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class MatchResult:
    affected: bool
    confidence: Confidence
    reason: str


def is_cve_affecting_product(
    product: dict[str, Any],
    affected_cpes: list[dict[str, Any]],
) -> MatchResult:
    """Main entry point: determine whether a CVE affects a product+version.

    affected_cpes is the list extracted from NVD raw_payload['configurations']
    (see extract_affected_cpes helper below).
    """
    if not affected_cpes:
        return MatchResult(
            affected=True,
            confidence=Confidence.UNCERTAIN,
            reason="no_cpe_data",
        )

    installed_version = (product.get("version") or "").strip()
    product_cpe_match_found = False

    for cpe_entry in affected_cpes:
        cpe_name = cpe_entry.get("criteria") or cpe_entry.get("cpe") or ""

        if not _product_matches_cpe_vendor_product(product, cpe_name):
            continue
        product_cpe_match_found = True

        if is_version_in_range(installed_version, cpe_entry):
            return MatchResult(
                affected=True,
                confidence=Confidence.CERTAIN,
                reason=f"version_in_range:{cpe_name}",
            )

    if product_cpe_match_found:
        return MatchResult(
            affected=False,
            confidence=Confidence.CERTAIN,
            reason=f"version_outside_all_ranges:{installed_version}",
        )

    return MatchResult(
        affected=True,
        confidence=Confidence.UNCERTAIN,
        reason="no_cpe_vendor_product_match",
    )


def extract_affected_cpes(raw_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk NVD 2.0 configurations tree and return a flat list of CPE match entries.

    Each entry has the shape:
      {"criteria": "cpe:2.3:...", "versionStartIncluding": ..., "versionEndExcluding": ...}
    """
    cpes: list[dict[str, Any]] = []
    for config in raw_payload.get("configurations") or []:
        for node in config.get("nodes") or []:
            cpes.extend(node.get("cpeMatch") or [])
            # Recurse into nested nodes (NVD uses 'children' in some entries)
            for child in node.get("children") or []:
                cpes.extend(child.get("cpeMatch") or [])
    return cpes
