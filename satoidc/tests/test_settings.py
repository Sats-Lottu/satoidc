import pytest

from satoidc.settings import PLACEHOLDER_SECRET, Settings


def test_session_cookie_https_only_defaults_to_environment():
    dev_settings = Settings(_env_file=None)
    prod_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        OAUTH2_JWT_ISS="https://issuer.example",
        SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
        OAUTH2_JWT_SECRET_KEY="jwt-secret",
    )

    assert dev_settings.session_cookie_https_only is False
    assert prod_settings.session_cookie_https_only is True


def test_session_cookie_https_only_can_be_enabled_before_production():
    settings = Settings(_env_file=None, SESSION_COOKIE_HTTPS_ONLY=True)

    assert settings.session_cookie_https_only is True


def test_production_rejects_placeholder_secrets():
    with pytest.raises(ValueError, match="SESSION_MIDDLEWARE_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY=PLACEHOLDER_SECRET,
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
        )

    with pytest.raises(ValueError, match="OAUTH2_JWT_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
            OAUTH2_JWT_SECRET_KEY=PLACEHOLDER_SECRET,
        )


def test_production_rejects_insecure_session_cookie_override():
    with pytest.raises(ValueError, match="SESSION_COOKIE_HTTPS_ONLY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
            SESSION_COOKIE_HTTPS_ONLY=False,
        )


def test_production_rejects_local_or_missing_issuer():
    with pytest.raises(ValueError, match="OAUTH2_JWT_ISS"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
        )

    with pytest.raises(ValueError, match="OAUTH2_JWT_ISS"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="",
            SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
        )


def test_database_urls_must_target_same_backend():
    with pytest.raises(ValueError, match="DATABASE_URL and SYNC_DATABASE_URL"):
        Settings(
            _env_file=None,
            DATABASE_URL="sqlite+aiosqlite:///satoidc.db",
            SYNC_DATABASE_URL=(
                "postgresql+psycopg://user:pass@database:5432/app_db"
            ),
        )


def test_database_urls_must_target_same_database():
    with pytest.raises(ValueError, match="DATABASE_URL and SYNC_DATABASE_URL"):
        Settings(
            _env_file=None,
            DATABASE_URL="postgresql+psycopg://user:pass@db:5432/app_db",
            SYNC_DATABASE_URL=(
                "postgresql+psycopg://user:pass@db:5432/other_db"
            ),
        )


def test_database_url_validation_accepts_sqlite_async_sync_pair():
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+aiosqlite:///satoidc.db",
        SYNC_DATABASE_URL="sqlite:///satoidc.db",
    )

    assert settings.DATABASE_URL == "sqlite+aiosqlite:///satoidc.db"


def test_database_url_validation_accepts_sqlite_memory_pair():
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        SYNC_DATABASE_URL="sqlite:///:memory:",
    )

    assert settings.SYNC_DATABASE_URL == "sqlite:///:memory:"


def test_database_url_validation_accepts_postgresql_pair():
    settings = Settings(
        _env_file=None,
        DATABASE_URL="postgresql+psycopg://user:pass@db:5432/app_db",
        SYNC_DATABASE_URL="postgresql+psycopg://user:pass@db:5432/app_db",
    )

    assert settings.SYNC_DATABASE_URL.endswith("/app_db")


def test_oidc_signing_backend_must_be_supported():
    Settings(_env_file=None, OIDC_SIGNING_BACKEND="database")
    Settings(_env_file=None, OIDC_SIGNING_BACKEND="transit")

    with pytest.raises(ValueError, match="OIDC_SIGNING_BACKEND"):
        Settings(_env_file=None, OIDC_SIGNING_BACKEND="unsupported")
