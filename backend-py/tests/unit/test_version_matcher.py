"""Unit tests for the version matcher — ported from version-matcher.service.js.

These are pure-function tests with no I/O. Each case is documented with the
WHY so regressions are immediately understandable.
"""
from __future__ import annotations

from app.resolution.version_matcher import (
    Confidence,
    compare_versions,
    extract_affected_cpes,
    extract_cpe_version,
    is_cve_affecting_product,
    is_version_in_range,
    normalise_slug,
    parse_cpe_vendor_product,
)

# ─── compare_versions ────────────────────────────────────────────────────────

class TestCompareVersions:
    def test_equal(self):
        assert compare_versions("1.2.3", "1.2.3") == 0

    def test_major_diff(self):
        assert compare_versions("2.0.0", "1.9.9") == 1
        assert compare_versions("1.0.0", "2.0.0") == -1

    def test_patch_diff(self):
        assert compare_versions("1.2.4", "1.2.3") == 1
        assert compare_versions("1.2.3", "1.2.4") == -1

    def test_openssl_patch_letters(self):
        # OpenSSL: 1.0.2k > 1.0.2j > 1.0.2a > 1.0.2
        assert compare_versions("1.0.2k", "1.0.2j") == 1
        assert compare_versions("1.0.2a", "1.0.2") == 1
        assert compare_versions("1.0.2", "1.0.2a") == -1

    def test_pre_release_less_than_release(self):
        # 2.0-beta9 < 2.0.0
        assert compare_versions("2.0-beta9", "2.0.0") == -1
        assert compare_versions("1.0-rc1", "1.0") == -1

    def test_pre_release_ordering(self):
        # -alpha < -beta < -rc
        assert compare_versions("1.0-alpha", "1.0-beta") == -1
        assert compare_versions("1.0-rc1", "1.0-beta") == 1

    def test_wildcard_returns_zero(self):
        assert compare_versions("*", "1.0.0") == 0
        assert compare_versions("1.0.0", "*") == 0
        assert compare_versions("*", "*") == 0

    def test_windows_build_numbers(self):
        assert compare_versions("10.0.19044.2006", "10.0.19044.2005") == 1

    def test_different_length_versions(self):
        # "1.2" treated as "1.2.0"
        assert compare_versions("1.2", "1.2.0") == 0
        assert compare_versions("1.2.1", "1.2") == 1

    def test_empty_and_none_like(self):
        assert compare_versions("", "1.0") == 0
        assert compare_versions("n/a", "1.0") == 0


# ─── is_version_in_range ─────────────────────────────────────────────────────

class TestIsVersionInRange:
    def _entry(self, **kwargs):
        return kwargs

    def test_within_inclusive_range(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndIncluding="2.0.0")
        assert is_version_in_range("1.5.0", entry) is True

    def test_below_start_inclusive(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndIncluding="2.0.0")
        assert is_version_in_range("0.9.9", entry) is False

    def test_above_end_inclusive(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndIncluding="2.0.0")
        assert is_version_in_range("2.0.1", entry) is False

    def test_at_start_inclusive_boundary(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndExcluding="2.0.0")
        assert is_version_in_range("1.0.0", entry) is True

    def test_at_end_exclusive_boundary(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndExcluding="2.0.0")
        assert is_version_in_range("2.0.0", entry) is False

    def test_start_exclusive(self):
        entry = self._entry(versionStartExcluding="1.0.0", versionEndIncluding="2.0.0")
        assert is_version_in_range("1.0.0", entry) is False
        assert is_version_in_range("1.0.1", entry) is True

    def test_no_range_wildcard_cpe_version(self):
        # No range bounds + wildcard CPE version → matches any version
        entry = {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}
        assert is_version_in_range("99.0.0", entry) is True

    def test_no_range_exact_cpe_version_match(self):
        entry = {"criteria": "cpe:2.3:a:vendor:product:1.18.0:*:*:*:*:*:*:*"}
        assert is_version_in_range("1.18.0", entry) is True
        assert is_version_in_range("1.18.1", entry) is False

    def test_wildcard_installed_always_matches(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndExcluding="2.0.0")
        assert is_version_in_range("*", entry) is True

    def test_empty_installed_always_matches(self):
        entry = self._entry(versionStartIncluding="1.0.0", versionEndExcluding="2.0.0")
        assert is_version_in_range("", entry) is True


# ─── is_cve_affecting_product ─────────────────────────────────────────────────

class TestIsCveAffectingProduct:
    def _product(self, name="nginx", vendor="nginx", version="1.18.0", cpe_keyword=None):
        return {"name": name, "vendor": vendor, "version": version, "normalized_cpe": cpe_keyword}

    def test_no_cpe_data_uncertain(self):
        result = is_cve_affecting_product(self._product(), [])
        assert result.affected is True
        assert result.confidence == Confidence.UNCERTAIN
        assert result.reason == "no_cpe_data"

    def test_version_in_range_certain(self):
        cpes = [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]
        result = is_cve_affecting_product(self._product(version="1.18.0"), cpes)
        assert result.affected is True
        assert result.confidence == Confidence.CERTAIN

    def test_version_outside_range_certain(self):
        cpes = [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]
        result = is_cve_affecting_product(self._product(version="1.21.0"), cpes)
        assert result.affected is False
        assert result.confidence == Confidence.CERTAIN

    def test_no_vendor_product_match_uncertain(self):
        # CVE is for apache:httpd, product is nginx
        cpes = [{"criteria": "cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*"}]
        result = is_cve_affecting_product(self._product(name="nginx", vendor="nginx"), cpes)
        assert result.affected is True
        assert result.confidence == Confidence.UNCERTAIN

    def test_direct_cpe_keyword_match(self):
        product = self._product(
            name="nginx", vendor="nginx", version="1.18.0",
            cpe_keyword="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
        )
        cpes = [{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.affected is True
        assert result.confidence == Confidence.CERTAIN

    def test_openssl_patch_letter_in_range(self):
        product = {"name": "openssl", "vendor": "openssl", "version": "1.0.2k",
                   "normalized_cpe": None}
        cpes = [{"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.2", "versionEndExcluding": "1.0.2u"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.affected is True
        assert result.confidence == Confidence.CERTAIN

    def test_openssl_patch_letter_beyond_fixed(self):
        # 1.0.2u is the fix → 1.0.2z (hypothetical patched) should be outside range
        product = {"name": "openssl", "vendor": "openssl", "version": "1.0.2z",
                   "normalized_cpe": None}
        cpes = [{"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0.2", "versionEndExcluding": "1.0.2u"}]
        result = is_cve_affecting_product(product, cpes)
        assert result.affected is False
        assert result.confidence == Confidence.CERTAIN


# ─── CPE string utilities ─────────────────────────────────────────────────────

def test_extract_cpe_version():
    assert extract_cpe_version("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*") == "1.18.0"
    assert extract_cpe_version("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*") == "*"
    assert extract_cpe_version("") is None


def test_parse_cpe_vendor_product():
    assert parse_cpe_vendor_product("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*") == "apache:log4j"
    assert parse_cpe_vendor_product("short") is None


def test_normalise_slug():
    assert normalise_slug("Apache Log4j") == "apache_log4j"
    assert normalise_slug("Microsoft Windows") == "microsoft_windows"
    assert normalise_slug("OpenSSL 3.0") == "openssl_3.0"


# ─── extract_affected_cpes ────────────────────────────────────────────────────

def test_extract_affected_cpes_flat():
    raw = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                             "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"},
                        ]
                    }
                ]
            }
        ]
    }
    cpes = extract_affected_cpes(raw)
    assert len(cpes) == 1
    assert cpes[0]["criteria"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


def test_extract_affected_cpes_empty():
    assert extract_affected_cpes({}) == []
    assert extract_affected_cpes({"configurations": []}) == []


def test_extract_affected_cpes_with_children():
    raw = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [],
                        "children": [
                            {"cpeMatch": [
                                {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
                            ]}
                        ]
                    }
                ]
            }
        ]
    }
    cpes = extract_affected_cpes(raw)
    assert len(cpes) == 1
