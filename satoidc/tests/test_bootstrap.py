from setup_wizard.bootstrap import (
    BootstrapStatus,
    RuntimeValueKind,
    check_database_ready,
    check_oidc_signing_ready,
    check_root_user_ready,
    env_with_persisted_generated_secrets,
    persist_generated_secrets,
    validate_bootstrap_environment,
)


def test_bootstrap_allows_development_defaults():
    report = validate_bootstrap_environment({"APP_ENV": "development"})

    assert report.can_start
    assert report.blocking_messages == []


def test_bootstrap_reports_production_operator_and_generated_values():
    report = validate_bootstrap_environment(
        {
            "APP_ENV": "production",
            "OAUTH2_JWT_ISS": "http://localhost:8000",
            "OAUTH2_JWT_SECRET_KEY": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
            "SESSION_MIDDLEWARE_SECRET_KEY": (
                "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
            ),
            "SESSION_COOKIE_HTTPS_ONLY": "false",
        }
    )

    assert not report.can_start
    assert {
        (check.name, check.kind, check.status)
        for check in report.checks
        if check.status == BootstrapStatus.BLOCKED
    } == {
        (
            "OAUTH2_JWT_ISS",
            RuntimeValueKind.OPERATOR_MANAGED,
            BootstrapStatus.BLOCKED,
        ),
        (
            "OAUTH2_JWT_SECRET_KEY",
            RuntimeValueKind.GENERATED,
            BootstrapStatus.BLOCKED,
        ),
        (
            "SESSION_MIDDLEWARE_SECRET_KEY",
            RuntimeValueKind.GENERATED,
            BootstrapStatus.BLOCKED,
        ),
        (
            "SETUP_GENERATED_SECRETS_PATH",
            RuntimeValueKind.GENERATED,
            BootstrapStatus.BLOCKED,
        ),
        (
            "SESSION_COOKIE_HTTPS_ONLY",
            RuntimeValueKind.OPERATOR_MANAGED,
            BootstrapStatus.BLOCKED,
        ),
    }


def test_bootstrap_accepts_generated_secret_persistence_path():
    report = validate_bootstrap_environment(
        {
            "APP_ENV": "production",
            "OAUTH2_JWT_ISS": "https://issuer.example",
            "OAUTH2_JWT_SECRET_KEY": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
            "SESSION_MIDDLEWARE_SECRET_KEY": (
                "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
            ),
            "SETUP_GENERATED_SECRETS_PATH": "/run/secrets/satoidc.env",
            "SESSION_COOKIE_HTTPS_ONLY": "true",
        }
    )

    assert {
        check.name
        for check in report.checks
        if check.status == BootstrapStatus.BLOCKED
    } == {
        "OAUTH2_JWT_SECRET_KEY",
        "SESSION_MIDDLEWARE_SECRET_KEY",
    }


def test_bootstrap_persists_generated_secrets(tmp_path):
    secret_file = tmp_path / "generated.env"
    env = {
        "APP_ENV": "production",
        "OAUTH2_JWT_ISS": "https://issuer.example",
        "OAUTH2_JWT_SECRET_KEY": "CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
        "SESSION_MIDDLEWARE_SECRET_KEY": (
            "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
        ),
        "SETUP_GENERATED_SECRETS_PATH": str(secret_file),
        "SESSION_COOKIE_HTTPS_ONLY": "true",
    }

    generated = persist_generated_secrets(env)
    merged_env = env_with_persisted_generated_secrets(env)
    first_file_contents = secret_file.read_text(encoding="utf-8")

    assert set(generated) == {
        "OAUTH2_JWT_SECRET_KEY",
        "SESSION_MIDDLEWARE_SECRET_KEY",
    }
    assert "CHANGE_ME" not in first_file_contents
    assert "export OAUTH2_JWT_SECRET_KEY=" in first_file_contents
    assert "export SESSION_MIDDLEWARE_SECRET_KEY=" in first_file_contents
    assert generated["OAUTH2_JWT_SECRET_KEY"] != (
        "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    )
    assert merged_env["OAUTH2_JWT_SECRET_KEY"] == generated[
        "OAUTH2_JWT_SECRET_KEY"
    ]
    assert validate_bootstrap_environment(merged_env).can_start

    persist_generated_secrets(env)

    assert secret_file.read_text(encoding="utf-8") == first_file_contents


def test_bootstrap_reports_database_url_mismatch_without_secrets():
    report = validate_bootstrap_environment(
        {
            "APP_ENV": "production",
            "OAUTH2_JWT_ISS": "https://issuer.example",
            "OAUTH2_JWT_SECRET_KEY": "jwt-secret",
            "SESSION_MIDDLEWARE_SECRET_KEY": "session-secret",
            "SESSION_COOKIE_HTTPS_ONLY": "true",
            "DATABASE_URL": (
                "postgresql+psycopg://user:secret@db:5432/app_db"
            ),
            "SYNC_DATABASE_URL": (
                "postgresql+psycopg://user:secret@db:5432/other_db"
            ),
        }
    )

    assert not report.can_start
    assert any(
        check.name == "DATABASE_URL/SYNC_DATABASE_URL"
        for check in report.checks
    )
    assert "secret" not in "\n".join(report.blocking_messages)


async def test_database_readiness_accepts_sqlite_memory():
    check = await check_database_ready("sqlite+aiosqlite:///:memory:")

    assert check.status == BootstrapStatus.OK


async def test_database_readiness_failure_hides_url_secrets(monkeypatch):
    class BrokenConnection:
        async def __aenter__(self):
            raise RuntimeError("postgresql://user:secret@db/app_db failed")

        async def __aexit__(self, exc_type, exc, traceback):
            return None

    class BrokenEngine:
        @staticmethod
        def connect():
            return BrokenConnection()

        @staticmethod
        async def dispose():
            return None

    monkeypatch.setattr(
        "setup_wizard.bootstrap.create_async_engine",
        lambda _url: BrokenEngine(),
    )

    check = await check_database_ready(
        "postgresql+psycopg://user:secret@db:5432/app_db"
    )

    assert check.status == BootstrapStatus.BLOCKED
    assert "secret" not in check.message


async def test_root_readiness_reports_missing_root(monkeypatch):
    async def missing_root():
        return False

    monkeypatch.setattr("setup_wizard.get_root.exists_root_user", missing_root)

    check = await check_root_user_ready()

    assert check.name == "root_permission"
    assert check.status == BootstrapStatus.BLOCKED


async def test_root_readiness_accepts_existing_root(monkeypatch):
    async def existing_root():
        return True

    monkeypatch.setattr(
        "setup_wizard.get_root.exists_root_user", existing_root
    )

    check = await check_root_user_ready()

    assert check.name == "root_permission"
    assert check.status == BootstrapStatus.OK


def test_oidc_signing_readiness_creates_active_key(db_session):
    check = check_oidc_signing_ready()

    assert check.name == "oidc_signing_key"
    assert check.status == BootstrapStatus.OK
