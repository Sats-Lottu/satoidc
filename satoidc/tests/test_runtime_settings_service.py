import pytest

from satoidc.models import SetupRuntimeSetting
from satoidc.services.runtime_settings import (
    MUTABLE_BY_KEY,
    RuntimeSettingValidationError,
    env_names_for_field,
    field_values_from_runtime_settings,
    upsert_runtime_setting,
    validate_runtime_setting_value,
)


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("instance_name", "  SatOIDC Lab  ", "SatOIDC Lab"),
        ("lnurl_k1_ttl_seconds", 60, 60),
        ("smtp_use_tls", True, True),
        ("session_cookie_https_only", None, None),
        ("email_sender_mode", "console", "console"),
        ("email_sender", "ops@example.com", "ops@example.com"),
        ("issuer", " https://issuer.example ", "https://issuer.example"),
        ("oidc_transit_mount", " transit ", "transit"),
        ("oidc_transit_addr", "https://vault.example", "https://vault.example"),
    ],
)
def test_validate_runtime_setting_value_normalizes_valid_payloads(
    key, value, expected
):
    assert (
        validate_runtime_setting_value(
            MUTABLE_BY_KEY[key],
            value,
            production=False,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("instance_name", "", "1-80 visible"),
        ("lnurl_k1_ttl_seconds", True, "integer"),
        ("lnurl_k1_ttl_seconds", 29, "greater than or equal"),
        ("lnurl_k1_ttl_seconds", 601, "less than or equal"),
        ("smtp_use_tls", "true", "boolean"),
        ("session_cookie_https_only", "false", "boolean or null"),
        ("session_cookie_https_only", False, "true or null"),
        ("instance_name", 123, "must be a string"),
        ("email_sender_mode", "sendmail", "must be one of"),
        ("email_sender", "not-an-email", "valid email"),
        ("oidc_audience", "\n", "non-empty"),
        ("smtp_host", "smtp\nexample", "no control chars"),
        ("public_base_url", "http://issuer.example", "public_base_url"),
        ("oidc_transit_addr", "ftp://vault.example", "oidc_transit_addr"),
    ],
)
def test_validate_runtime_setting_value_rejects_invalid_payloads(
    key, value, match
):
    with pytest.raises(ValueError, match=match):
        validate_runtime_setting_value(
            MUTABLE_BY_KEY[key],
            value,
            production=True,
        )


def test_field_values_from_runtime_settings_filters_invalid_rows():
    values = field_values_from_runtime_settings(
        [
            ("instance_name", '"Persisted SatOIDC"'),
            ("unknown", '"ignored"'),
            ("smtp_port", "70000"),
            ("email_sender_mode", '"console"'),
            ("smtp_use_tls", "not-json"),
            ("session_cookie_https_only", "false"),
            ("oidc_transit_mount", "null"),
        ],
        production=False,
    )

    assert values == {
        "SERVICE_NAME": "Persisted SatOIDC",
        "EMAIL_SENDER_MODE": "console",
        "SESSION_COOKIE_HTTPS_ONLY": False,
    }


async def test_upsert_runtime_setting_creates_and_updates_rows(db_session):
    created = await upsert_runtime_setting(
        db_session,
        key="instance_name",
        value=" SatOIDC Lab ",
        production=False,
        updated_by="admin-1",
    )
    updated = await upsert_runtime_setting(
        db_session,
        key="instance_name",
        value="SatOIDC Ops",
        production=False,
        source="setup",
        updated_by="admin-2",
    )

    stored = await db_session.get(SetupRuntimeSetting, "instance_name")

    assert created.key == updated.key == "instance_name"
    assert stored.value == '"SatOIDC Ops"'
    assert stored.source == "setup"
    assert stored.updated_by == "admin-2"
    assert stored.secret_ref is None


async def test_upsert_runtime_setting_rejects_unknown_key(db_session):
    with pytest.raises(RuntimeSettingValidationError) as exc_info:
        await upsert_runtime_setting(
            db_session,
            key="not_wizard_owned",
            value="x",
            production=False,
        )

    assert exc_info.value.errors == {
        "not_wizard_owned": "is not wizard-owned"
    }


def test_env_names_for_field_returns_known_aliases():
    assert "SATOIDC_INSTANCE_NAME" in env_names_for_field("SERVICE_NAME")
    assert env_names_for_field("UNKNOWN_FIELD") == ()
