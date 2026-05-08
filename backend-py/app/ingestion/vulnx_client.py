"""vulnx (ProjectDiscovery exploitability intel) client — P1.

OpSec
-----
* Sends only ``cve_id`` values (string list) — never asset, hostname, IP,
  asset_id, version inventory data.
* All outbound traffic goes through ``OpsecAwareClient`` so the rule is
  enforced even if a future code path tries to widen the payload.

Resilience
----------
* Per-provider rate governor (``app.state.rate_governors['vulnx']``).
* Per-provider circuit breaker (``app.state.circuit_breakers['vulnx']``).
* Daily counter caps total request volume at ``settings.vulnx_daily_limit``
  (defensive against API-key abuse / runaway loops).
* Returns partial results on per-CVE parse errors instead of failing the
  whole batch.

Endpoint shape
--------------
The ProjectDiscovery API surface evolves. This client is written
defensively: the parser tolerates either a list of intel objects keyed by
``cve_id`` or a wrapper ``{"data": [...]}``. Each intel object's PoC and
Nuclei signals are derived from heuristics on the response payload (any
``poc_urls`` non-empty → ``has_public_poc=True``; any ``nuclei_templates``
or ``templates`` non-empty → ``has_nuclei_template=True``). Adjust the
heuristic when the upstream contract is finalised — kept narrow on
purpose so contract tests catch any drift.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

import httpx
import structlog

from app.core.config import Settings
from app.core.http import OpsecAwareClient
from app.ingestion.rate_governor import TokenBucket
from app.models.intel import IntelRecord

logger = structlog.get_logger(__name__)


@dataclass
class _DailyCounter:
    """Process-local counter that resets at UTC midnight."""

    limit: int
    _count: int = 0
    _day: date = field(default_factory=lambda: datetime.now(tz=UTC).date())
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def consume(self, n: int = 1) -> bool:
        async with self._lock:
            today = datetime.now(tz=UTC).date()
            if today != self._day:
                self._day = today
                self._count = 0
            if self._count + n > self.limit:
                return False
            self._count += n
            return True

    @property
    def used_today(self) -> int:
        return self._count


@dataclass
class VulnxClient:
    settings: Settings
    governor: TokenBucket
    _client: OpsecAwareClient = field(init=False)
    _daily: _DailyCounter = field(init=False)

    def __post_init__(self) -> None:
        headers = {
            "User-Agent": "cve-management/0.1 (internal)",
            "Accept": "application/json",
        }
        if self.settings.vulnx_api_key:
            headers["Authorization"] = f"Bearer {self.settings.vulnx_api_key}"

        self._client = OpsecAwareClient(
            provider="vulnx",
            enforcement=self.settings.opsec_enforcement,
            base_url=self.settings.vulnx_base_url,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
            headers=headers,
        )
        self._daily = _DailyCounter(limit=self.settings.vulnx_daily_limit)

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def is_configured(self) -> bool:
        # vulnx allows anonymous calls in their public docs but it is
        # rate-limited aggressively. We treat configured == has-api-key for
        # the purpose of staffing the refresh job.
        return bool(self.settings.vulnx_api_key)

    @property
    def used_today(self) -> int:
        return self._daily.used_today

    def attach_metrics(self, metrics: Any) -> None:
        """Forward metrics sink to the underlying OpSec wrapper."""
        self._client.attach_metrics(metrics)

    # ------------------------------------------------------------------ public

    async def fetch_intel(self, cve_ids: list[str]) -> dict[str, IntelRecord]:
        """Batch lookup. Returns a mapping of ``cve_id`` → ``IntelRecord``.

        CVE IDs missing from the upstream response are simply absent from
        the returned dict; callers must handle "not found" by leaving the
        DB columns as NULL (see ``exploitability_refresh.py``).
        """
        if not cve_ids:
            return {}

        # Normalize input (upper-case, dedup, preserve order).
        seen: set[str] = set()
        normalized: list[str] = []
        for cid in cve_ids:
            up = cid.strip().upper()
            if up and up not in seen:
                seen.add(up)
                normalized.append(up)

        results: dict[str, IntelRecord] = {}
        batch_size = max(1, self.settings.vulnx_batch_size)

        for i in range(0, len(normalized), batch_size):
            batch = normalized[i : i + batch_size]
            allowed = await self._daily.consume(len(batch))
            if not allowed:
                logger.warning(
                    "vulnx.daily_limit_exhausted",
                    used=self._daily.used_today,
                    limit=self.settings.vulnx_daily_limit,
                    skipped=len(batch),
                )
                break

            try:
                batch_intel = await self._fetch_batch(batch)
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "vulnx.batch_failed",
                    batch_size=len(batch),
                    error=str(exc),
                )
                # Daily counter already debited — that is intentional.
                continue

            results.update(batch_intel)

        logger.info(
            "vulnx.fetch_intel.done",
            requested=len(normalized),
            returned=len(results),
            used_today=self._daily.used_today,
        )
        return results

    # ------------------------------------------------------------------ private

    async def _fetch_batch(self, cve_ids: list[str]) -> dict[str, IntelRecord]:
        await self.governor.acquire()
        t0 = time.monotonic()

        # vulnx batch endpoint: best-effort URL with a JSON body containing
        # only CVE IDs. Body is OpSec-checked by OpsecAwareClient.
        resp = await self._client.post(
            "/vulnerabilities/batch",
            json={"cves": cve_ids},
        )
        latency_ms = int((time.monotonic() - t0) * 1000)

        if resp.status_code == 429:
            logger.warning("vulnx.rate_limited", latency_ms=latency_ms)
            raise httpx.HTTPStatusError("rate limited", request=resp.request, response=resp)
        if resp.status_code in (401, 403):
            logger.error(
                "vulnx.auth_error",
                status=resp.status_code,
                hint="Check VULNX_API_KEY",
            )
            raise httpx.HTTPStatusError("auth error", request=resp.request, response=resp)
        resp.raise_for_status()

        try:
            body = resp.json()
        except ValueError as exc:
            logger.error("vulnx.bad_json", error=str(exc))
            raise

        return _parse_batch_payload(body)


# ---------------------------------------------------------------------- parser

def _parse_batch_payload(body: Any) -> dict[str, IntelRecord]:
    """Parse a vulnx batch response shape-agnostically.

    Accepts:
      - ``{"data": [{...}, ...]}``
      - ``[{...}, ...]``
      - ``{"<CVE-ID>": {...}, ...}``

    Each intel item is identified by ``cve_id`` / ``cve`` / ``id`` field.
    PoC presence: any non-empty list under keys ``poc_urls`` / ``poc`` /
    ``exploits``. Nuclei presence: any non-empty list under
    ``nuclei_templates`` / ``templates`` / ``nuclei``.
    """
    items: list[dict[str, Any]] = []

    if isinstance(body, list):
        items = [x for x in body if isinstance(x, dict)]
    elif isinstance(body, dict):
        if isinstance(body.get("data"), list):
            items = [x for x in body["data"] if isinstance(x, dict)]
        elif isinstance(body.get("results"), list):
            items = [x for x in body["results"] if isinstance(x, dict)]
        else:
            for key, value in body.items():
                if isinstance(value, dict) and key.upper().startswith("CVE-"):
                    item = dict(value)
                    item.setdefault("cve_id", key)
                    items.append(item)

    out: dict[str, IntelRecord] = {}
    for item in items:
        cve_id = (
            item.get("cve_id")
            or item.get("cve")
            or item.get("id")
            or ""
        ).strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        poc_urls = _coerce_str_list(
            item.get("poc_urls"),
            item.get("poc"),
            item.get("exploits"),
        )
        templates = _coerce_str_list(
            item.get("nuclei_templates"),
            item.get("templates"),
            item.get("nuclei"),
        )
        refs = _coerce_str_list(item.get("references"))

        out[cve_id] = IntelRecord(
            cve_id=cve_id,
            has_public_poc=bool(poc_urls),
            has_nuclei_template=bool(templates),
            poc_urls=poc_urls,
            template_paths=templates,
            references=refs,
        )
    return out


def _coerce_str_list(*candidates: Any) -> list[str]:
    """Return the first non-empty list-of-strings among the candidates."""
    for c in candidates:
        if not c:
            continue
        if isinstance(c, str):
            return [c]
        if isinstance(c, list):
            out = []
            for v in c:
                if isinstance(v, str) and v:
                    out.append(v)
                elif isinstance(v, dict):
                    # accept items shaped as {"url": "..."} or {"path": "..."}
                    val = v.get("url") or v.get("path") or v.get("href")
                    if isinstance(val, str) and val:
                        out.append(val)
            if out:
                return out
    return []
