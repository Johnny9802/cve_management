from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = "postgresql://cve_user:cve_password@localhost:5433/cve_management"

    # Cache / Queue broker (Valkey, Redis-compatible)
    redis_url: str = "redis://:cve_redis@localhost:6380"

    # API Keys
    nvd_api_key: str = ""
    vulncheck_api_key: str = ""
    opencve_api_key: str = ""
    vulnx_api_key: str = ""

    # vulnx (ProjectDiscovery exploitability intel) — P1
    vulnx_base_url: str = "https://cloud.projectdiscovery.io/api/v1"
    vulnx_refresh_interval_hours: int = 24
    vulnx_daily_limit: int = 10_000
    vulnx_batch_size: int = 50
    vulnx_staleness_days: int = 7
    # ``intel:*`` Redis cache TTL for the /api/cves/{id}/intel endpoint
    intel_cache_ttl_seconds: int = 600

    # OpSec — egress monitor (P10)
    opsec_enforcement: bool = True   # if False: log only, do not raise
    # Comma-separated host suffixes that are *trusted* to receive bodies that
    # may contain numeric strings resembling IPs (CPE versions etc.).
    # The OpsecAwareClient still scans for IP/MAC/asset_id field names but
    # tolerates noisy match cases for these hosts.
    opsec_relaxed_hosts: str = ""

    # Server
    backend_py_port: int = 8000
    allowed_origin: str = "http://localhost:3000"
    environment: str = "development"
    log_level: str = "INFO"

    # External service base URLs (never hardcode paths here — only base)
    vulncheck_base_url: str = "https://api.vulncheck.com"
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    circl_base_url: str = "https://vulnerability.circl.lu/api/search"
    opencve_base_url: str = "https://app.opencve.io/api"

    # NVD rate limiting (milliseconds between requests)
    nvd_request_delay_ms: int = 6000   # without API key
    nvd_request_delay_key_ms: int = 600  # with API key

    # CIRCL daily hard limit
    circl_daily_limit: int = 20000

    # CPE resolution confidence thresholds (RapidFuzz score 0-100)
    cpe_auto_match_threshold: float = 85.0
    cpe_confirm_threshold: float = 60.0

    # Sync schedule (hours)
    delta_sync_interval_hours: int = 1
    kev_refresh_interval_hours: int = 6
    epss_refresh_interval_hours: int = 24

    # Run Alembic migrations automatically at startup (safe: idempotent)
    auto_migrate: bool = True

    # ── Auth (Sprint 1 — see docs/adr/0001-auth-strategy.md) ─────────────
    # JWT secret. In production this MUST be overridden via env var; the
    # lifespan validator refuses to start if the dev sentinel leaks
    # into environment="production".
    jwt_secret: str = "dev-secret-do-not-use-in-prod-change-me-immediately"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60
    refresh_token_ttl_days: int = 7

    # Initial admin user seeded on first startup if the users table is
    # empty. Both must be set; otherwise the seed is a no-op and the
    # operator is expected to provision the first admin out-of-band.
    admin_email: str = ""
    admin_password: str = ""

    # ── Observability (Sprint 3 — S3.6) ──────────────────────────────────
    # Sentry DSN. Empty = disabled (sentry_sdk treats DSN="" as a no-op
    # via our wrapper in app/core/sentry.py). The lifespan logs once at
    # startup so you can tell from the boot log whether it's active.
    sentry_dsn: str = ""
    sentry_traces_sample_rate: float = 0.0

    @property
    def nvd_request_delay(self) -> float:
        if self.nvd_api_key:
            return self.nvd_request_delay_key_ms / 1000
        return self.nvd_request_delay_ms / 1000


@lru_cache
def get_settings() -> Settings:
    return Settings()
