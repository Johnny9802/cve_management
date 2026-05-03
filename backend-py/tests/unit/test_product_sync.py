"""Unit tests for product sync helpers (pure functions — no I/O)."""
from __future__ import annotations

import pytest

from app.workers.product_sync import _build_search_pattern


class TestBuildSearchPattern:
    def test_cpe_vendor_product_extracted(self):
        product = {
            "normalized_cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            "name": "nginx",
            "vendor": "nginx",
        }
        pattern = _build_search_pattern(product)
        assert pattern == "cpe:2.3:%:nginx:nginx:%"

    def test_cpe_os_part(self):
        product = {
            "normalized_cpe": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
            "name": "Ubuntu Linux",
            "vendor": "Canonical",
        }
        pattern = _build_search_pattern(product)
        assert pattern == "cpe:2.3:%:canonical:ubuntu_linux:%"

    def test_no_cpe_falls_back_to_name_vendor(self):
        product = {
            "normalized_cpe": None,
            "name": "OpenSSL",
            "vendor": "OpenSSL Project",
        }
        pattern = _build_search_pattern(product)
        assert "openssl" in pattern.lower()

    def test_no_cpe_no_vendor_uses_name_only(self):
        product = {"normalized_cpe": None, "name": "Apache Httpd", "vendor": None}
        pattern = _build_search_pattern(product)
        assert "apache_httpd" in pattern

    def test_pattern_has_wildcards(self):
        product = {
            "normalized_cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "name": "Product",
            "vendor": "Vendor",
        }
        pattern = _build_search_pattern(product)
        assert pattern.startswith("cpe:2.3:%:")
        assert pattern.endswith(":%")

    def test_invalid_cpe_falls_back(self):
        product = {
            "normalized_cpe": "not_a_valid_cpe",
            "name": "MyApp",
            "vendor": "Acme",
        }
        pattern = _build_search_pattern(product)
        assert "myapp" in pattern or "acme" in pattern


# ─── Version matching integration with product sync ────────────────────────

class TestVersionMatcherInSyncContext:
    """Validate that the product dict shape used in sync matches what version_matcher expects."""

    def test_product_dict_keys(self):
        from app.resolution.version_matcher import is_cve_affecting_product
        product = {
            "name": "nginx",
            "vendor": "nginx",
            "version": "1.18.0",
            "normalized_cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        }
        cpes = [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.affected is True

    def test_no_matching_cpe_returns_uncertain(self):
        from app.resolution.version_matcher import is_cve_affecting_product, Confidence
        product = {"name": "nginx", "vendor": "nginx", "version": "2.0.0", "normalized_cpe": None}
        cpes = [{"criteria": "cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.confidence == Confidence.UNCERTAIN
        assert result.affected is True  # conservative fallback

    def test_version_outside_range_excluded(self):
        from app.resolution.version_matcher import is_cve_affecting_product, Confidence
        product = {"name": "nginx", "vendor": "nginx", "version": "1.22.0", "normalized_cpe": None}
        cpes = [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.affected is False
        assert result.confidence == Confidence.CERTAIN
