import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import SetupRuntimeSetting
from satoidc.runtime_config import (
    RUNTIME_ENV_VARS,
    RuntimeConfigError,
    validate_issuer_url,
    validate_public_url,
)


@dataclass(frozen=True)
class RuntimeSettingSpec:
    key: str
    field_name: str
    value_type: type
    minimum: int | None = None
    maximum: int | None = None
    choices: frozenset[str] | None = None
    high_impact: bool = False


MUTABLE_RUNTIME_SETTINGS: tuple[RuntimeSettingSpec, ...] = (
    RuntimeSettingSpec("instance_name", "SERVICE_NAME", str),
    RuntimeSettingSpec(
        "public_base_url", "EMAIL_PUBLIC_BASE_URL", str, high_impact=True
    ),
    RuntimeSettingSpec("issuer", "OAUTH2_JWT_ISS", str, high_impact=True),
    RuntimeSettingSpec(
        "session_cookie_https_only",
        "SESSION_COOKIE_HTTPS_ONLY",
        bool | None,
    ),
    RuntimeSettingSpec(
        "lnurl_k1_ttl_seconds", "LNURL_K1_TTL_SECONDS", int, 30, 600
    ),
    RuntimeSettingSpec("oidc_audience", "OAUTH2_JWT_AUDIENCE", str),
    RuntimeSettingSpec(
        "token_lifetime_seconds",
        "OAUTH2_TOKEN_EXPIRES_IN",
        int,
        60,
        86400,
        high_impact=True,
    ),
    RuntimeSettingSpec(
        "jwks_cache_ttl_seconds", "OIDC_JWKS_CACHE_TTL_SECONDS", int, 0, 86400
    ),
    RuntimeSettingSpec(
        "key_retention_margin_seconds",
        "OIDC_KEY_RETENTION_MARGIN_SECONDS",
        int,
        60,
        604800,
        high_impact=True,
    ),
    RuntimeSettingSpec(
        "email_sender_mode",
        "EMAIL_SENDER_MODE",
        str,
        choices=frozenset({"disabled", "console", "smtp"}),
    ),
    RuntimeSettingSpec("email_sender", "SMTP_FROM_EMAIL", str),
    RuntimeSettingSpec(
        "email_verification_token_ttl_seconds",
        "EMAIL_VERIFICATION_TOKEN_TTL_SECONDS",
        int,
        300,
        604800,
    ),
    RuntimeSettingSpec(
        "email_reset_token_ttl_seconds",
        "EMAIL_RESET_TOKEN_TTL_SECONDS",
        int,
        300,
        86400,
    ),
    RuntimeSettingSpec(
        "email_token_min_request_interval_seconds",
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        int,
        0,
        86400,
    ),
    RuntimeSettingSpec("smtp_host", "SMTP_HOST", str),
    RuntimeSettingSpec("smtp_port", "SMTP_PORT", int, 1, 65535),
    RuntimeSettingSpec("smtp_username", "SMTP_USERNAME", str),
    RuntimeSettingSpec("smtp_use_tls", "SMTP_USE_TLS", bool),
    RuntimeSettingSpec("smtp_start_tls", "SMTP_START_TLS", bool),
    RuntimeSettingSpec(
        "oidc_signing_backend",
        "OIDC_SIGNING_BACKEND",
        str,
        choices=frozenset({"database", "transit"}),
        high_impact=True,
    ),
    RuntimeSettingSpec(
        "oidc_transit_addr", "OIDC_TRANSIT_ADDR", str, high_impact=True
    ),
    RuntimeSettingSpec(
        "oidc_transit_mount", "OIDC_TRANSIT_MOUNT", str, high_impact=True
    ),
    RuntimeSettingSpec(
        "oidc_transit_key_name",
        "OIDC_TRANSIT_KEY_NAME",
        str,
        high_impact=True,
    ),
)

MUTABLE_BY_KEY = {spec.key: spec for spec in MUTABLE_RUNTIME_SETTINGS}
MUTABLE_BY_FIELD = {spec.field_name: spec for spec in MUTABLE_RUNTIME_SETTINGS}
FIELD_ENV_NAMES = {
    spec.field_name: tuple(
        name
        for candidate in (spec.satoidc_name, spec.current_name)
        if (name := candidate)
    )
    for spec in RUNTIME_ENV_VARS
}
MAX_INSTANCE_NAME_LENGTH = 80
CONTROL_CHAR_LIMIT = 32
NON_EMPTY_NO_CONTROL_KEYS = {
    "oidc_audience",
    "oidc_transit_mount",
    "oidc_transit_key_name",
}


class RuntimeSettingValidationError(ValueError):
    def __init__(self, errors: dict[str, str]) -> None:
        self.errors = errors
        super().__init__("Runtime setting payload is invalid.")


def env_names_for_field(field_name: str) -> tuple[str, ...]:
    return FIELD_ENV_NAMES.get(field_name, ())


def validate_runtime_setting_value(  # noqa: PLR0912
    spec: RuntimeSettingSpec,
    value: Any,
    *,
    production: bool,
) -> Any:
    if spec.value_type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("must be an integer")
        if spec.minimum is not None and value < spec.minimum:
            raise ValueError(
                f"must be greater than or equal to {spec.minimum}"
            )
        if spec.maximum is not None and value > spec.maximum:
            raise ValueError(f"must be less than or equal to {spec.maximum}")
        return value

    if spec.value_type is bool:
        if not isinstance(value, bool):
            raise ValueError("must be a boolean")
        return value

    if spec.value_type == bool | None:
        if value is not None and not isinstance(value, bool):
            raise ValueError("must be a boolean or null")
        if production and value is False:
            raise ValueError("must be true or null in production")
        return value

    if not isinstance(value, str):
        raise ValueError("must be a string")

    normalized = value.strip()
    if spec.key == "instance_name":
        if not 1 <= len(normalized) <= MAX_INSTANCE_NAME_LENGTH or any(
            ord(char) < CONTROL_CHAR_LIMIT for char in normalized
        ):
            raise ValueError("must be 1-80 visible characters")
    elif spec.key == "issuer":
        validate_issuer_url(normalized, production=production)
    elif spec.key == "public_base_url":
        validate_public_url(
            normalized,
            name="public_base_url",
            production=production,
        )
    elif spec.key == "oidc_transit_addr" and normalized:
        validate_public_url(
            normalized,
            name="oidc_transit_addr",
            production=production,
        )
    elif spec.key in NON_EMPTY_NO_CONTROL_KEYS:
        if not normalized or any(
            ord(char) < CONTROL_CHAR_LIMIT for char in normalized
        ):
            raise ValueError("must be non-empty and contain no control chars")
    elif spec.key in {"smtp_host", "smtp_username"}:
        if any(ord(char) < CONTROL_CHAR_LIMIT for char in normalized):
            raise ValueError("must contain no control chars")
    elif spec.key == "email_sender":
        if "@" not in normalized or any(
            ord(char) < CONTROL_CHAR_LIMIT for char in normalized
        ):
            raise ValueError("must be a valid email address")

    if spec.choices and normalized not in spec.choices:
        allowed = ", ".join(sorted(spec.choices))
        raise ValueError(f"must be one of: {allowed}")
    return normalized


def field_values_from_runtime_settings(
    rows: list[tuple[str, str | None]],
    *,
    production: bool,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, raw_value in rows:
        spec = MUTABLE_BY_KEY.get(key)
        if spec is None or raw_value is None:
            continue
        try:
            decoded = json.loads(raw_value)
            values[spec.field_name] = validate_runtime_setting_value(
                spec, decoded, production=production
            )
        except (
            RuntimeConfigError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            continue
    return values


async def upsert_runtime_setting(  # noqa: PLR0913
    session: AsyncSession,
    *,
    key: str,
    value: Any,
    production: bool,
    source: str = "admin_reconfigure",
    updated_by: str | None = None,
) -> SetupRuntimeSetting:
    spec = MUTABLE_BY_KEY.get(key)
    if spec is None:
        raise RuntimeSettingValidationError({key: "is not wizard-owned"})
    normalized = validate_runtime_setting_value(
        spec, value, production=production
    )
    setting = await session.get(SetupRuntimeSetting, key)
    if setting is None:
        setting = SetupRuntimeSetting(
            key=key,
            value=json.dumps(normalized, separators=(",", ":")),
            source=source,
            updated_by=updated_by,
        )
        session.add(setting)
    else:
        setting.value = json.dumps(normalized, separators=(",", ":"))
        setting.secret_ref = None
        setting.source = source
        setting.updated_by = updated_by
    await session.commit()
    await session.refresh(setting)
    return setting
