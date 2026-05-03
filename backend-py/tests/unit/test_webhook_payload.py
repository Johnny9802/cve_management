"""Unit tests for webhook payload helpers (P7).

These tests do not require a database — they cover the deterministic
serialisation, HMAC signing, and the OpSec contract on payloads.
"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from app.services.webhooks import (
    ALLOWED_EVENT_TYPES,
    build_finding_event,
    mask_secret,
    serialize_payload,
    sign,
)


class TestPayloadShape:
    def test_required_fields_only(self):
        payload = build_finding_event(
            event_type="finding.kev_match",
            cve_id="CVE-2024-0001",
            severity="CRITICAL",
            priority_score=92,
            affected_count=3,
            is_kev=True,
            has_public_poc=True,
            has_nuclei_template=False,
        )
        assert set(payload) >= {
            "event_type", "cve_id", "severity", "priority_score",
            "affected_count", "is_kev", "has_public_poc",
            "has_nuclei_template", "timestamp",
        }
        # OpSec: NO asset fields whatsoever.
        for forbidden in ("hostname", "ip_address", "asset_id", "mac"):
            assert forbidden not in payload

    def test_unknown_event_rejected(self):
        with pytest.raises(ValueError):
            build_finding_event(
                event_type="finding.totally_made_up",
                cve_id="CVE-2024-0001",
                severity="HIGH",
                priority_score=80,
                affected_count=1,
                is_kev=False,
                has_public_poc=None,
                has_nuclei_template=None,
            )

    def test_extra_whitelist_filtering(self):
        payload = build_finding_event(
            event_type="finding.exploitability_changed",
            cve_id="CVE-2024-1",
            severity="HIGH",
            priority_score=80,
            affected_count=2,
            is_kev=False,
            has_public_poc=True,
            has_nuclei_template=True,
            extra={"delta_score": 8, "secret_attacker_data": "leak"},
        )
        assert payload["delta_score"] == 8
        assert "secret_attacker_data" not in payload

    def test_all_event_types_known(self):
        # Sanity: each event type the client allows must be in the
        # frozenset, otherwise build_finding_event refuses it.
        for ev in ALLOWED_EVENT_TYPES:
            built = build_finding_event(
                event_type=ev,
                cve_id="CVE-2024-9999",
                severity="HIGH",
                priority_score=85,
                affected_count=1,
                is_kev=True,
                has_public_poc=False,
                has_nuclei_template=False,
            )
            assert built["event_type"] == ev


class TestSignature:
    def test_signature_format(self):
        payload = build_finding_event(
            event_type="finding.kev_match",
            cve_id="CVE-2024-0001",
            severity="CRITICAL",
            priority_score=92,
            affected_count=3,
            is_kev=True,
            has_public_poc=True,
            has_nuclei_template=False,
        )
        body = serialize_payload(payload)
        sig = sign(body, "topsecret")
        assert sig.startswith("sha256=")

        manual = hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
        assert sig == f"sha256={manual}"

    def test_signature_is_stable_over_serialize(self):
        # Two builds with identical data must produce identical signatures
        # (modulo the timestamp, which is the only non-deterministic part).
        a = serialize_payload({"k": "v", "n": 1})
        b = serialize_payload({"n": 1, "k": "v"})
        assert a == b  # sort_keys=True ensures stable order


class TestSecretMasking:
    def test_short_secret(self):
        assert mask_secret("abc") == "***"

    def test_long_secret(self):
        masked = mask_secret("supersecretvalue1234")
        assert masked is not None
        assert masked.startswith("supe")
        assert masked.endswith("1234")
        assert "supersecretvalue1234" not in masked

    def test_none_secret(self):
        assert mask_secret(None) is None
