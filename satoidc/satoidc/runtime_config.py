import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote, urlsplit

from sqlalchemy.engine import URL, make_url

PRODUCTION_ENVIRONMENTS = {"production", "prod"}
PLACEHOLDER_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
LOCAL_ISSUERS = {"http://localhost:8000", "http://127.0.0.1:8000"}
MIN_PRODUCTION_SECRET_LENGTH = 32
SECRET_MASK = "********"
LOGGER = logging.getLogger(__name__)


class RuntimeConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeEnvVar:
    field_name: str
    current_name: str
    satoidc_name: str | None = None
    supports_file: bool = False
    secret: bool = False


RUNTIME_ENV_VARS: tuple[RuntimeEnvVar, ...] = (
    RuntimeEnvVar("SERVICE_NAME", "SERVICE_NAME", "SATOIDC_INSTANCE_NAME"),
    RuntimeEnvVar("APP_ENV", "APP_ENV", "SATOIDC_APP_ENV"),
    RuntimeEnvVar(
        "EMAIL_PUBLIC_BASE_URL",
        "EMAIL_PUBLIC_BASE_URL",
        "SATOIDC_PUBLIC_BASE_URL",
    ),
    RuntimeEnvVar("OAUTH2_JWT_ISS", "OAUTH2_JWT_ISS", "SATOIDC_ISSUER"),
    RuntimeEnvVar(
        "DATABASE_URL",
        "DATABASE_URL",
        "SATOIDC_DATABASE_URL",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar(
        "SYNC_DATABASE_URL",
        "SYNC_DATABASE_URL",
        "SATOIDC_SYNC_DATABASE_URL",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar(
        "SESSION_MIDDLEWARE_SECRET_KEY",
        "SESSION_MIDDLEWARE_SECRET_KEY",
        "SATOIDC_SECRET_KEY",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar(
        "OAUTH2_JWT_SECRET_KEY",
        "OAUTH2_JWT_SECRET_KEY",
        "SATOIDC_OIDC_SECRET_KEY",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar(
        "SESSION_COOKIE_HTTPS_ONLY",
        "SESSION_COOKIE_HTTPS_ONLY",
        "SATOIDC_SESSION_COOKIE_HTTPS_ONLY",
    ),
    RuntimeEnvVar(
        "LNURL_K1_TTL_SECONDS",
        "LNURL_K1_TTL_SECONDS",
        "SATOIDC_LNURL_K1_TTL_SECONDS",
    ),
    RuntimeEnvVar(
        "OAUTH2_JWT_AUDIENCE",
        "OAUTH2_JWT_AUDIENCE",
        "SATOIDC_OIDC_AUDIENCE",
    ),
    RuntimeEnvVar(
        "OAUTH2_JWT_ALG",
        "OAUTH2_JWT_ALG",
        "SATOIDC_OIDC_SIGNING_ALG",
    ),
    RuntimeEnvVar(
        "OAUTH2_TOKEN_EXPIRES_IN",
        "OAUTH2_TOKEN_EXPIRES_IN",
        "SATOIDC_TOKEN_LIFETIME_SECONDS",
    ),
    RuntimeEnvVar(
        "OIDC_JWKS_CACHE_TTL_SECONDS",
        "OIDC_JWKS_CACHE_TTL_SECONDS",
        "SATOIDC_OIDC_JWKS_CACHE_TTL_SECONDS",
    ),
    RuntimeEnvVar(
        "OIDC_KEY_RETENTION_MARGIN_SECONDS",
        "OIDC_KEY_RETENTION_MARGIN_SECONDS",
        "SATOIDC_OIDC_KEY_RETENTION_MARGIN_SECONDS",
    ),
    RuntimeEnvVar(
        "OIDC_SIGNING_BACKEND",
        "OIDC_SIGNING_BACKEND",
        "SATOIDC_OIDC_SIGNING_BACKEND",
    ),
    RuntimeEnvVar(
        "OIDC_TRANSIT_ADDR",
        "OIDC_TRANSIT_ADDR",
        "SATOIDC_OIDC_TRANSIT_ADDR",
    ),
    RuntimeEnvVar(
        "OIDC_TRANSIT_TOKEN",
        "OIDC_TRANSIT_TOKEN",
        "SATOIDC_OIDC_TRANSIT_TOKEN",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar(
        "OIDC_TRANSIT_MOUNT",
        "OIDC_TRANSIT_MOUNT",
        "SATOIDC_OIDC_TRANSIT_MOUNT",
    ),
    RuntimeEnvVar(
        "OIDC_TRANSIT_KEY_NAME",
        "OIDC_TRANSIT_KEY_NAME",
        "SATOIDC_OIDC_TRANSIT_KEY_NAME",
    ),
    RuntimeEnvVar(
        "EMAIL_SENDER_MODE",
        "EMAIL_SENDER_MODE",
        "SATOIDC_EMAIL_SENDER_MODE",
    ),
    RuntimeEnvVar(
        "SMTP_FROM_EMAIL", "SMTP_FROM_EMAIL", "SATOIDC_EMAIL_SENDER"
    ),
    RuntimeEnvVar(
        "EMAIL_VERIFICATION_TOKEN_TTL_SECONDS",
        "EMAIL_VERIFICATION_TOKEN_TTL_SECONDS",
        "SATOIDC_EMAIL_VERIFICATION_TOKEN_TTL_SECONDS",
    ),
    RuntimeEnvVar(
        "EMAIL_RESET_TOKEN_TTL_SECONDS",
        "EMAIL_RESET_TOKEN_TTL_SECONDS",
        "SATOIDC_EMAIL_RESET_TOKEN_TTL_SECONDS",
    ),
    RuntimeEnvVar(
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        "SATOIDC_EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
    ),
    RuntimeEnvVar("SMTP_HOST", "SMTP_HOST", "SATOIDC_SMTP_HOST"),
    RuntimeEnvVar("SMTP_PORT", "SMTP_PORT", "SATOIDC_SMTP_PORT"),
    RuntimeEnvVar(
        "SMTP_USERNAME", "SMTP_USERNAME", "SATOIDC_SMTP_USERNAME"
    ),
    RuntimeEnvVar(
        "SMTP_PASSWORD",
        "SMTP_PASSWORD",
        "SATOIDC_SMTP_PASSWORD",
        supports_file=True,
        secret=True,
    ),
    RuntimeEnvVar("SMTP_USE_TLS", "SMTP_USE_TLS", "SATOIDC_SMTP_TLS"),
    RuntimeEnvVar(
        "SMTP_START_TLS", "SMTP_START_TLS", "SATOIDC_SMTP_STARTTLS"
    ),
    RuntimeEnvVar(
        "SATOIDC_ADMIN_USERNAME",
        "",
        "SATOIDC_ADMIN_USERNAME",
    ),
    RuntimeEnvVar(
        "SATOIDC_ADMIN_EMAIL",
        "",
        "SATOIDC_ADMIN_EMAIL",
    ),
    RuntimeEnvVar(
        "SATOIDC_ADMIN_PASSWORD",
        "",
        "SATOIDC_ADMIN_PASSWORD",
        supports_file=True,
        secret=True,
    ),
)


def is_production_environment(app_env: str) -> bool:
    return app_env.lower() in PRODUCTION_ENVIRONMENTS


def is_placeholder_secret(value: str | None) -> bool:
    return not value or value == PLACEHOLDER_SECRET


def mask_secret(value: str | None) -> str:
    return SECRET_MASK if value else ""


def _read_secret_file(variable_name: str, raw_path: str) -> str:
    path = Path(raw_path)
    try:
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise RuntimeConfigError(
            f"{variable_name} points to a secret file that cannot be read"
        ) from exc

    if not value:
        raise RuntimeConfigError(
            f"{variable_name} points to an empty secret file"
        )
    return value


def _resolve_variable(
    spec: RuntimeEnvVar, env: Mapping[str, str]
) -> str | None:
    names = [name for name in (spec.satoidc_name, spec.current_name) if name]
    for name in names:
        direct_value = env.get(name)
        file_name = f"{name}_FILE"
        file_path = env.get(file_name) if spec.supports_file else None

        if direct_value is not None:
            if file_path:
                LOGGER.warning(
                    "%s is set; ignoring %s for %s",
                    name,
                    file_name,
                    spec.field_name,
                )
            return direct_value

        if file_path:
            return _read_secret_file(file_name, file_path)

    return None


def resolved_runtime_env_settings(
    env: Mapping[str, str],
) -> dict[str, str]:
    normalized_env = {name.upper(): value for name, value in env.items()}
    resolved: dict[str, str] = {}
    for spec in RUNTIME_ENV_VARS:
        value = _resolve_variable(spec, normalized_env)
        if value is None:
            continue
        if (
            spec.satoidc_name
            and spec.satoidc_name in normalized_env
            and spec.current_name in normalized_env
        ):
            LOGGER.warning(
                "%s is set; ignoring legacy %s for %s",
                spec.satoidc_name,
                spec.current_name,
                spec.field_name,
            )
        resolved[spec.field_name] = value
    return resolved


def is_operator_issuer_missing(value: str | None) -> bool:
    if not value or not value.strip():
        return True
    return value.rstrip("/") in LOCAL_ISSUERS


def _url_is_absolute_http_url(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _url_is_local(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.hostname in {"localhost", "127.0.0.1", "::1"}


def validate_public_url(
    value: str | None, *, name: str, production: bool
) -> None:
    if not value:
        return
    if not _url_is_absolute_http_url(value):
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")
    parsed = urlsplit(value)
    if production and parsed.scheme != "https":
        raise ValueError(f"{name} must use HTTPS in production")
    if production and _url_is_local(value):
        raise ValueError(f"{name} must not use a local URL in production")


def validate_issuer_url(value: str | None, *, production: bool) -> None:
    if is_operator_issuer_missing(value):
        if production:
            raise ValueError(
                "OAUTH2_JWT_ISS must be configured to the public issuer "
                "URL in production"
            )
        return

    issuer = value.strip()
    validate_public_url(issuer, name="OAUTH2_JWT_ISS", production=production)
    parsed = urlsplit(issuer)
    if parsed.query or parsed.fragment:
        raise ValueError("OAUTH2_JWT_ISS must not include query or fragment")


def validate_production_secret(value: str | None, *, name: str) -> None:
    if is_placeholder_secret(value):
        raise ValueError(f"{name} must be changed in production")
    if len(value or "") < MIN_PRODUCTION_SECRET_LENGTH:
        raise ValueError(
            f"{name} must be at least "
            f"{MIN_PRODUCTION_SECRET_LENGTH} characters in production"
        )


def _backend_family(url: URL) -> str:
    return url.drivername.split("+", maxsplit=1)[0]


def _sqlite_database(url: URL) -> str:
    database = unquote(url.database or "")
    if database == ":memory:":
        return database
    return str(Path(database).as_posix())


def database_url_identity(
    raw_url: str,
) -> tuple[str, str | None, int | None, str]:
    url = make_url(raw_url)
    backend = _backend_family(url)

    if backend == "sqlite":
        return (backend, None, None, _sqlite_database(url))

    return (
        backend,
        url.host,
        url.port,
        unquote((url.database or "").lstrip("/")),
    )


def database_urls_match(database_url: str, sync_database_url: str) -> bool:
    return database_url_identity(database_url) == database_url_identity(
        sync_database_url
    )


def validate_database_url_pair(
    database_url: str, sync_database_url: str
) -> None:
    if not database_urls_match(database_url, sync_database_url):
        raise ValueError(
            "DATABASE_URL and SYNC_DATABASE_URL must point to the same "
            "database"
        )
