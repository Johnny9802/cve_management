"""CPE normalizer — maps free-form user strings to CPE 2.3 URIs.

Pipeline:
  1. Check cpe_resolutions table (DB cache) and Redis cache.
  2. If already resolved, return cached result.
  3. Otherwise:
     a. If input already looks like a CPE 2.3 string → validate and accept.
     b. Extract (vendor_hint, product_hint, version_hint) from the input.
     c. Query the local CVE mirror for candidate CPE vendor:product pairs.
     d. RapidFuzz Token Sort Ratio against candidates.
     e. score >= auto_threshold  → confidence=certain
        score >= confirm_threshold → confidence=uncertain (user may confirm)
        score <  confirm_threshold → no match
  4. Persist resolution to DB + Redis.

Thresholds (configurable via Settings):
  cpe_auto_match_threshold   = 85  (auto-accept)
  cpe_confirm_threshold      = 60  (flag for review, still used as uncertain)
"""
from __future__ import annotations

import re

import asyncpg
import structlog
from rapidfuzz import fuzz
from rapidfuzz import process as rfprocess

from app.core.config import Settings
from app.models.product import CpeResolution

logger = structlog.get_logger(__name__)

_CPE_PREFIX = "cpe:2.3:"
_CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:[^:]+:[^:]+")

# How many candidate CPE pairs to pull from the DB for fuzzy matching
_CANDIDATE_LIMIT = 500

# SQL: extract unique (vendor, product, part) tuples from ingested CVE data
_CANDIDATES_SQL = """
SELECT DISTINCT
    split_part(cpe_entry->>'criteria', ':', 4) AS vendor,
    split_part(cpe_entry->>'criteria', ':', 5) AS product,
    split_part(cpe_entry->>'criteria', ':', 3) AS part
FROM cves,
     jsonb_array_elements(raw_payload->'configurations') AS cfg,
     jsonb_array_elements(cfg->'nodes')                   AS nd,
     jsonb_array_elements(nd->'cpeMatch')                 AS cpe_entry
WHERE raw_payload->'configurations' IS NOT NULL
  AND raw_payload->'configurations' != 'null'::jsonb
  AND (
      split_part(cpe_entry->>'criteria', ':', 5) ILIKE $1
      OR split_part(cpe_entry->>'criteria', ':', 4) ILIKE $1
  )
LIMIT $2
"""


def _is_cpe_string(s: str) -> bool:
    return bool(_CPE_RE.match(s.lower()))


def _extract_hints(input_str: str) -> tuple[str, str, str]:
    """Heuristically split 'Ubuntu Linux 22.04' → (vendor='', product='ubuntu_linux', version='22.04').

    Returns (vendor_hint, product_hint, version_hint) all lowercased.
    Version hint is the last token if it looks numeric; otherwise empty.
    """
    tokens = input_str.strip().split()
    if not tokens:
        return "", "", ""

    # Last token is numeric → version
    version_hint = ""
    if tokens and re.match(r"^\d[\d.]*", tokens[-1]):
        version_hint = tokens[-1]
        tokens = tokens[:-1]

    # Remaining tokens → product (spaces → underscores)
    product_hint = "_".join(t.lower() for t in tokens) if tokens else ""
    return "", product_hint, version_hint


def _build_cpe(part: str, vendor: str, product: str, version: str = "*") -> str:
    """Construct a CPE 2.3 URI from components."""
    ver = version if version else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


async def _fetch_candidates(
    pool: asyncpg.Pool,
    keyword: str,
) -> list[dict[str, str]]:
    """Query the local CVE mirror for CPE vendor:product pairs matching keyword."""
    pattern = f"%{keyword}%"
    try:
        rows = await pool.fetch(_CANDIDATES_SQL, pattern, _CANDIDATE_LIMIT)
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("cpe_normalizer.candidate_query_error", error=str(exc))
        return []


def _fuzzy_match(
    product_hint: str,
    candidates: list[dict[str, str]],
    auto_threshold: float,
    confirm_threshold: float,
) -> tuple[dict[str, str] | None, float]:
    """Return (best_candidate, score) or (None, 0.0) if below confirm_threshold."""
    if not candidates:
        return None, 0.0

    # Build a list of strings to match against: "{vendor}:{product}"
    choices = [f"{c['vendor']}:{c['product']}" for c in candidates]
    result = rfprocess.extractOne(
        product_hint,
        choices,
        scorer=fuzz.token_sort_ratio,
    )
    if result is None:
        return None, 0.0

    best_str, score, idx = result
    if score < confirm_threshold:
        return None, score

    return candidates[idx], score


class CpeNormalizer:
    def __init__(self, pool: asyncpg.Pool, settings: Settings) -> None:
        self._pool = pool
        self._auto_threshold = settings.cpe_auto_match_threshold
        self._confirm_threshold = settings.cpe_confirm_threshold

    async def normalize(self, input_str: str) -> CpeResolution | None:
        """Resolve input_str to a CPE 2.3 string.

        Returns None when no match exceeds confirm_threshold.
        Caller is responsible for persisting the result via ResolutionCache.
        """
        s = input_str.strip()
        if not s:
            return None

        # Already a CPE string → accept as-is with certain confidence
        if _is_cpe_string(s):
            return CpeResolution(
                input_string=s,
                resolved_cpe=s,
                confidence="certain",
                match_score=100.0,
                resolved_by="auto",
            )

        _, product_hint, version_hint = _extract_hints(s)
        if not product_hint:
            return None

        candidates = await _fetch_candidates(self._pool, product_hint)
        if not candidates:
            logger.debug("cpe_normalizer.no_candidates", input=s, hint=product_hint)
            return None

        best, score = _fuzzy_match(
            product_hint,
            candidates,
            self._auto_threshold,
            self._confirm_threshold,
        )
        if best is None:
            logger.debug("cpe_normalizer.below_threshold", input=s, score=score)
            return None

        confidence = "certain" if score >= self._auto_threshold else "uncertain"
        resolved_cpe = _build_cpe(
            part=best.get("part", "a"),
            vendor=best["vendor"],
            product=best["product"],
            version=version_hint,
        )

        logger.info(
            "cpe_normalizer.resolved",
            input=s,
            cpe=resolved_cpe,
            score=round(score, 1),
            confidence=confidence,
        )
        return CpeResolution(
            input_string=s,
            resolved_cpe=resolved_cpe,
            confidence=confidence,
            match_score=round(score, 2),
            resolved_by="auto",
        )
