"""Unit tests for the audit masking helper (P9 partial).

These tests are pure-function — no DB. They confirm that secrets, tokens,
api keys, and webhook URLs are scrubbed before persistence.
"""
from __future__ import annotations

from app.services.audit import mask_sensitive


class TestMaskSensitive:
    def test_secret_field_masked(self):
        out = mask_sensitive({"name": "x", "secret": "super"})
        assert out == {"name": "x", "secret": "***"}

    def test_password_field_masked(self):
        out = mask_sensitive({"username": "u", "password": "p"})
        assert out["password"] == "***"

    def test_api_key_variants_masked(self):
        for key in ("api_key", "API-KEY", "ApiKey"):
            assert mask_sensitive({key: "v"})[key] == "***"

    def test_token_field_masked(self):
        out = mask_sensitive({"access_token": "abc", "id_token": "xyz"})
        assert out == {"access_token": "***", "id_token": "***"}

    def test_authorization_header_masked(self):
        out = mask_sensitive({"Authorization": "Bearer xyz"})
        assert out["Authorization"] == "***"

    def test_url_path_stripped(self):
        out = mask_sensitive({"url": "https://hooks.slack.com/services/T0/B0/abc"})
        assert out["url"].startswith("https://hooks.slack.com")
        assert "abc" not in out["url"]
        assert out["url"].endswith("/***")

    def test_nested_dicts(self):
        out = mask_sensitive({"webhook": {"name": "ok", "secret": "leak"}})
        assert out["webhook"]["secret"] == "***"
        assert out["webhook"]["name"] == "ok"

    def test_lists_walked(self):
        out = mask_sensitive([{"secret": "a"}, {"name": "b"}])
        assert out[0]["secret"] == "***"
        assert out[1]["name"] == "b"

    def test_scalars_unchanged(self):
        assert mask_sensitive("plain string") == "plain string"
        assert mask_sensitive(42) == 42
        assert mask_sensitive(None) is None
        assert mask_sensitive(True) is True

    def test_idempotent(self):
        first = mask_sensitive({"secret": "a"})
        assert mask_sensitive(first) == first

    def test_no_false_positive_on_innocent_field(self):
        assert mask_sensitive({"description": "this contains the word secret in text"}) == {
            "description": "this contains the word secret in text"
        }
