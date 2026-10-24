"""Application settings.

All runtime configuration comes from environment variables (optionally a
local ``.env`` file during development), is validated by pydantic-settings,
and is exposed as a single immutable object attached to ``app.state``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CraftPass runtime configuration (see .env.example for documentation)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Public identity ---------------------------------------------------
    issuer_url: str = "https://auth.labcraft.me"
    cookie_domain: str = ".labcraft.me"
    default_redirect_url: str = "https://dash.stream.labcraft.me"
    session_cookie_name: str = "craftpass_sso"
    csrf_cookie_name: str = "craftpass_csrf"
    session_ttl_days: int = 30

    # -- Storage -------------------------------------------------------------
    data_dir: Path = Path("/data")

    # -- Bootstrap ------------------------------------------------------------
    setup_token: str = ""

    # -- Rate limiting ----------------------------------------------------------
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    # -- Argon2id (OWASP Password Storage Cheat Sheet: 19 MiB, t=2, p=1) ------
    argon2_time_cost: int = 2
    argon2_memory_kib: int = 19456
    argon2_parallelism: int = 1

    # -- Token lifetimes, in seconds -----------------------------------------------
    auth_code_ttl: int = 60
    id_token_ttl: int = 600
    access_token_ttl: int = 3600

    # -- Misc ----------------------------------------------------------------------
    secure_cookies: bool = True
    audit_max_rows: int = 1000

    @property
    def issuer(self) -> str:
        """Issuer URL without a trailing slash (used in JWTs and discovery)."""
        return self.issuer_url.rstrip("/")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "craftpass.db"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def cookie_suffix(self) -> str:
        """COOKIE_DOMAIN without the leading dot, lowercased."""
        return self.cookie_domain.lstrip(".").lower()

    @property
    def session_ttl_seconds(self) -> int:
        return self.session_ttl_days * 86400


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings used by the module-level ``app`` in craftpass.main."""
    return Settings()
