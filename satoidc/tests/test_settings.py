import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from satoidc.enums import JwkAlgEnum
from satoidc.models import SetupRuntimeSetting, table_registry
from satoidc.runtime_config import PLACEHOLDER_SECRET, mask_secret
from satoidc.settings import Settings

STRONG_SESSION_SECRET = "s" * 32
STRONG_OIDC_SECRET = "o" * 32


def test_jwk_alg_enum_tracks_authlib_joserfc_jws_algorithms():
    assert {algorithm.value for algorithm in JwkAlgEnum} == {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }


def test_session_cookie_https_only_defaults_to_environment():
    dev_settings = Settings(_env_file=None)
    prod_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        OAUTH2_JWT_ISS="https://issuer.example",
        SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
        OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
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
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
        )

    with pytest.raises(ValueError, match="OAUTH2_JWT_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY=PLACEHOLDER_SECRET,
        )


def test_production_rejects_short_secrets():
    with pytest.raises(ValueError, match="SESSION_MIDDLEWARE_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY="short",
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
        )

    with pytest.raises(ValueError, match="OAUTH2_JWT_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY="short",
        )


def test_production_rejects_insecure_session_cookie_override():
    with pytest.raises(ValueError, match="SESSION_COOKIE_HTTPS_ONLY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
            SESSION_COOKIE_HTTPS_ONLY=False,
        )


def test_production_rejects_local_or_missing_issuer():
    with pytest.raises(ValueError, match="OAUTH2_JWT_ISS"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
        )

    with pytest.raises(ValueError, match="OAUTH2_JWT_ISS"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
        )


def test_issuer_rejects_query_and_fragment():
    with pytest.raises(ValueError, match="query or fragment"):
        Settings(_env_file=None, OAUTH2_JWT_ISS="https://issuer.example?a=b")

    with pytest.raises(ValueError, match="query or fragment"):
        Settings(_env_file=None, OAUTH2_JWT_ISS="https://issuer.example#frag")


def test_production_rejects_insecure_public_base_url():
    with pytest.raises(ValueError, match="EMAIL_PUBLIC_BASE_URL"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            OAUTH2_JWT_ISS="https://issuer.example",
            EMAIL_PUBLIC_BASE_URL="http://issuer.example",
            SESSION_MIDDLEWARE_SECRET_KEY=STRONG_SESSION_SECRET,
            OAUTH2_JWT_SECRET_KEY=STRONG_OIDC_SECRET,
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


def test_oidc_signing_algorithm_supports_v1_rsa_contract():
    for algorithm in JwkAlgEnum:
        Settings(_env_file=None, OAUTH2_JWT_ALG=algorithm.value)

    with pytest.raises(ValueError, match="OAUTH2_JWT_ALG"):
        Settings(_env_file=None, OAUTH2_JWT_ALG="ES256")


def test_satoidc_alias_wins_over_current_env(monkeypatch, caplog):
    monkeypatch.setenv("OAUTH2_JWT_ISS", "https://legacy.example")
    monkeypatch.setenv("SATOIDC_ISSUER", "https://issuer.example")

    settings = Settings(_env_file=None)

    assert settings.OAUTH2_JWT_ISS == "https://issuer.example"
    assert "https://issuer.example" not in caplog.text
    assert "https://legacy.example" not in caplog.text
    assert "ignoring legacy OAUTH2_JWT_ISS" in caplog.text


def test_direct_secret_wins_over_file(monkeypatch, tmp_path, caplog):
    secret_path = tmp_path / "secret"
    secret_path.write_text("file-secret\n", encoding="utf-8")
    direct_secret = "direct-secret"
    monkeypatch.setenv("SATOIDC_SECRET_KEY", direct_secret)
    monkeypatch.setenv("SATOIDC_SECRET_KEY_FILE", str(secret_path))

    settings = Settings(_env_file=None)

    assert settings.SESSION_MIDDLEWARE_SECRET_KEY == direct_secret
    assert "file-secret" not in caplog.text
    assert direct_secret not in caplog.text
    assert "ignoring SATOIDC_SECRET_KEY_FILE" in caplog.text


def test_secret_file_resolution_strips_trailing_newlines(
    monkeypatch, tmp_path
):
    secret_path = tmp_path / "smtp-password"
    secret_path.write_text("smtp-secret\r\n\n", encoding="utf-8")
    monkeypatch.setenv("SATOIDC_SMTP_PASSWORD_FILE", str(secret_path))

    settings = Settings(_env_file=None)

    assert settings.SMTP_PASSWORD == "smtp-secret"


def test_secret_file_resolution_supports_dotenv(tmp_path):
    secret_path = tmp_path / "session-secret"
    secret_path.write_text(f"{STRONG_SESSION_SECRET}\n", encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text(
        f"SATOIDC_SECRET_KEY_FILE={secret_path}\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_path)

    assert settings.SESSION_MIDDLEWARE_SECRET_KEY == STRONG_SESSION_SECRET


def test_current_secret_file_name_is_supported(monkeypatch, tmp_path):
    secret_path = tmp_path / "transit-token"
    secret_path.write_text("transit-secret\n", encoding="utf-8")
    monkeypatch.setenv("OIDC_TRANSIT_TOKEN_FILE", str(secret_path))

    settings = Settings(_env_file=None)

    assert settings.OIDC_TRANSIT_TOKEN == "transit-secret"


def test_missing_secret_file_fails_clearly(monkeypatch, tmp_path):
    missing_path = tmp_path / "missing"
    monkeypatch.setenv("SATOIDC_SECRET_KEY_FILE", str(missing_path))

    with pytest.raises(ValueError, match="SATOIDC_SECRET_KEY_FILE"):
        Settings(_env_file=None)


def test_empty_secret_file_fails_clearly(monkeypatch, tmp_path):
    secret_path = tmp_path / "empty"
    secret_path.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("SATOIDC_SECRET_KEY_FILE", str(secret_path))

    with pytest.raises(ValueError, match="empty secret file"):
        Settings(_env_file=None)


def test_mask_secret_never_returns_secret_value():
    assert mask_secret("super-secret") == "********"
    assert not mask_secret("")
    assert not mask_secret(None)


def test_persisted_runtime_setting_loads_after_env_sources(tmp_path):
    database_path = tmp_path / "settings.db"
    sync_url = f"sqlite:///{database_path.as_posix()}"
    async_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    engine = create_engine(sync_url)
    table_registry.metadata.create_all(
        engine, tables=[SetupRuntimeSetting.__table__]
    )
    with Session(engine) as session:
        session.add(
            SetupRuntimeSetting(
                key="instance_name",
                value='"Persisted SatOIDC"',
                source="admin_reconfigure",
            )
        )
        session.commit()
    engine.dispose()

    settings = Settings(
        _env_file=None,
        DATABASE_URL=async_url,
        SYNC_DATABASE_URL=sync_url,
    )

    assert settings.SERVICE_NAME == "Persisted SatOIDC"


def test_env_locked_setting_wins_over_persisted_value(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "settings.db"
    sync_url = f"sqlite:///{database_path.as_posix()}"
    async_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    engine = create_engine(sync_url)
    table_registry.metadata.create_all(
        engine, tables=[SetupRuntimeSetting.__table__]
    )
    with Session(engine) as session:
        session.add(
            SetupRuntimeSetting(
                key="instance_name",
                value='"Persisted SatOIDC"',
                source="admin_reconfigure",
            )
        )
        session.commit()
    engine.dispose()
    monkeypatch.setenv("SATOIDC_INSTANCE_NAME", "Env SatOIDC")

    settings = Settings(
        _env_file=None,
        DATABASE_URL=async_url,
        SYNC_DATABASE_URL=sync_url,
    )

    assert settings.SERVICE_NAME == "Env SatOIDC"
