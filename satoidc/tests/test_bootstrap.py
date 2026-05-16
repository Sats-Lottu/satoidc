from setup_wizard.bootstrap import (
    BootstrapStatus,
    RuntimeValueKind,
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
            "SESSION_COOKIE_HTTPS_ONLY",
            RuntimeValueKind.OPERATOR_MANAGED,
            BootstrapStatus.BLOCKED,
        ),
    }


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
