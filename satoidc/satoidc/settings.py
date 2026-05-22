import os
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

from satoidc.enums import JwkAlgEnum
from satoidc.runtime_config import (
    is_production_environment,
    resolved_runtime_env_settings,
    validate_database_url_pair,
    validate_issuer_url,
    validate_production_secret,
    validate_public_url,
)

SUPPORTED_OIDC_SIGNING_ALGORITHMS = {
    algorithm.value for algorithm in JwkAlgEnum
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    SERVICE_NAME: str = "SatOIDC"
    DOMAIN: str = ""
    APP_ENV: str = "development"

    # Database settings
    DATABASE_URL: str = "sqlite+aiosqlite:///satoidc.db"
    SYNC_DATABASE_URL: str = "sqlite:///satoidc.db"

    # LNURL-AUTH settings
    LNURL_K1_TTL_SECONDS: int = 60

    # OAUTH2 JWT settings
    OAUTH2_JWT_ISS: str = "http://localhost:8000"
    OAUTH2_JWT_AUDIENCE: str = "SatOIDC-clients"
    OAUTH2_JWT_SECRET_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    OAUTH2_JWT_ALG: str = "RS256"
    OAUTH2_TOKEN_EXPIRES_IN: int = 300
    OIDC_JWKS_CACHE_TTL_SECONDS: int = 300
    OIDC_KEY_RETENTION_MARGIN_SECONDS: int = 900
    OIDC_SIGNING_BACKEND: str = "database"
    OIDC_TRANSIT_ADDR: str = ""
    OIDC_TRANSIT_TOKEN: str = ""
    OIDC_TRANSIT_MOUNT: str = "transit"
    OIDC_TRANSIT_KEY_NAME: str = "satoidc-id-token"

    EMAIL_SENDER_MODE: str = "disabled"
    EMAIL_PUBLIC_BASE_URL: str = ""
    EMAIL_VERIFICATION_TOKEN_TTL_SECONDS: int = 86400
    EMAIL_RESET_TOKEN_TTL_SECONDS: int = 1800
    EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS: int = 60
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    SMTP_START_TLS: bool = False
    SMTP_FROM_EMAIL: str = "no-reply@satoidc.local"

    SESSION_MIDDLEWARE_SECRET_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    SESSION_COOKIE_HTTPS_ONLY: bool | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        def runtime_env_settings():
            return resolved_runtime_env_settings(
                {
                    **getattr(dotenv_settings, "env_vars", {}),
                    **os.environ,
                }
            )

        return (
            init_settings,
            runtime_env_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )

    @property
    def is_production(self) -> bool:
        return is_production_environment(self.APP_ENV)

    @property
    def session_cookie_https_only(self) -> bool:
        if self.SESSION_COOKIE_HTTPS_ONLY is not None:
            return self.SESSION_COOKIE_HTTPS_ONLY
        return self.is_production

    def model_post_init(self, __context: Any) -> None:
        validate_database_url_pair(self.DATABASE_URL, self.SYNC_DATABASE_URL)
        if self.OIDC_SIGNING_BACKEND not in {"database", "transit"}:
            raise ValueError(
                "OIDC_SIGNING_BACKEND must be either 'database' or 'transit'"
            )
        if self.OAUTH2_JWT_ALG not in SUPPORTED_OIDC_SIGNING_ALGORITHMS:
            supported = ", ".join(sorted(SUPPORTED_OIDC_SIGNING_ALGORITHMS))
            raise ValueError(
                "OAUTH2_JWT_ALG must be one of the v1 supported "
                f"algorithms: {supported}"
            )
        if self.EMAIL_SENDER_MODE not in {"disabled", "console", "smtp"}:
            raise ValueError(
                "EMAIL_SENDER_MODE must be 'disabled', 'console', or 'smtp'"
            )

        validate_issuer_url(
            self.OAUTH2_JWT_ISS, production=self.is_production
        )
        validate_public_url(
            self.EMAIL_PUBLIC_BASE_URL,
            name="EMAIL_PUBLIC_BASE_URL",
            production=self.is_production,
        )

        if not self.is_production:
            return

        validate_production_secret(
            self.SESSION_MIDDLEWARE_SECRET_KEY,
            name="SESSION_MIDDLEWARE_SECRET_KEY",
        )
        validate_production_secret(
            self.OAUTH2_JWT_SECRET_KEY,
            name="OAUTH2_JWT_SECRET_KEY",
        )
        if not self.session_cookie_https_only:
            raise ValueError(
                "SESSION_COOKIE_HTTPS_ONLY must be enabled in production"
            )


ENV = Settings()
