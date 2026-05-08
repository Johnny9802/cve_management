"""Unit tests for CPE normalizer helpers (pure-function parts)."""
from __future__ import annotations

from app.resolution.cpe_normalizer import (
    _build_cpe,
    _extract_hints,
    _is_cpe_string,
)


class TestIsCpeString:
    def test_valid_cpe(self):
        assert _is_cpe_string("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*") is True
        assert _is_cpe_string("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*") is True

    def test_partial_cpe_rejected(self):
        assert _is_cpe_string("cpe:2.3:a:vendor") is False

    def test_free_text_rejected(self):
        assert _is_cpe_string("Ubuntu Linux 22.04") is False
        assert _is_cpe_string("nginx 1.18") is False


class TestExtractHints:
    def test_product_and_version(self):
        _, product, version = _extract_hints("nginx 1.18.0")
        assert product == "nginx"
        assert version == "1.18.0"

    def test_multi_word_product(self):
        _, product, version = _extract_hints("Ubuntu Linux 22.04")
        assert product == "ubuntu_linux"
        assert version == "22.04"

    def test_no_version(self):
        _, product, version = _extract_hints("Apache Log4j")
        assert product == "apache_log4j"
        assert version == ""

    def test_empty_string(self):
        vendor, product, version = _extract_hints("")
        assert product == ""
        assert version == ""

    def test_single_token_numeric_is_version(self):
        _, product, version = _extract_hints("openssl 3.0.1")
        assert product == "openssl"
        assert version == "3.0.1"


class TestBuildCpe:
    def test_with_version(self):
        cpe = _build_cpe("a", "nginx", "nginx", "1.18.0")
        assert cpe == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_without_version_defaults_to_wildcard(self):
        cpe = _build_cpe("o", "canonical", "ubuntu_linux", "")
        assert cpe == "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"

    def test_os_part(self):
        cpe = _build_cpe("o", "centos", "centos", "7")
        assert cpe.startswith("cpe:2.3:o:centos:centos:7:")
