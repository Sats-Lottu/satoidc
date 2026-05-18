import argparse
import asyncio
import logging
import os
import secrets
import shlex
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Mapping

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, User
from satoidc.runtime_config import (
    is_operator_issuer_missing,
    is_placeholder_secret,
    is_production_environment,
    resolved_runtime_env_settings,
    validate_database_url_pair,
)
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
)

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///satoidc.db"
DEFAULT_SYNC_DATABASE_URL = "sqlite:///satoidc.db"
GENERATED_SECRETS_PATH = "SETUP_GENERATED_SECRETS_PATH"
GENERATED_SECRET_NAMES = (
    "OAUTH2_JWT_SECRET_KEY",
    "SESSION_MIDDLEWARE_SECRET_KEY",
)
ADMIN_USERNAME_VAR = "SATOIDC_ADMIN_USERNAME"
ADMIN_EMAIL_VAR = "SATOIDC_ADMIN_EMAIL"
ADMIN_PASSWORD_VAR = "SATOIDC_ADMIN_PASSWORD"
LOGGER = logging.getLogger(__name__)


class RuntimeValueKind(StrEnum):
    GENERATED = "generated"
    OPERATOR_MANAGED = "operator-managed"
    OPTIONAL = "optional"


class BootstrapStatus(StrEnum):
    OK = "ok"
    BLOCKED = "blocked"


class RootBootstrapStatus(StrEnum):
    CREATED = "created"
    SKIPPED_EXISTING_ADMIN = "skipped_existing_admin"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class BootstrapCheck:
    name: str
    kind: RuntimeValueKind
    status: BootstrapStatus
    message: str


@dataclass(frozen=True)
class BootstrapReport:
    checks: tuple[BootstrapCheck, ...]

    @property
    def can_start(self) -> bool:
        return all(
            check.status == BootstrapStatus.OK for check in self.checks
        )

    @property
    def blocking_messages(self) -> list[str]:
        return [
            check.message
            for check in self.checks
            if check.status == BootstrapStatus.BLOCKED
        ]


@dataclass(frozen=True)
class RootBootstrapResult:
    status: RootBootstrapStatus
    message: str
    user_id: str | None = None

    @property
    def created(self) -> bool:
        return self.status == RootBootstrapStatus.CREATED

    @property
    def can_start(self) -> bool:
        return self.status in {
            RootBootstrapStatus.CREATED,
            RootBootstrapStatus.SKIPPED_EXISTING_ADMIN,
        }


def _combine_reports(*reports: BootstrapReport) -> BootstrapReport:
    checks: list[BootstrapCheck] = []
    for report in reports:
        checks.extend(report.checks)
    return BootstrapReport(tuple(checks))


def _env_value(
    env: Mapping[str, str], name: str, default: str | None = None
) -> str | None:
    value = env.get(name, default)
    return value.strip() if value is not None else None


def _normalized_env(env: Mapping[str, str]) -> dict[str, str]:
    return {name.upper(): value for name, value in env.items()}


def _check(
    name: str,
    kind: RuntimeValueKind,
    blocked: bool,
    message: str,
) -> BootstrapCheck:
    return BootstrapCheck(
        name=name,
        kind=kind,
        status=BootstrapStatus.BLOCKED if blocked else BootstrapStatus.OK,
        message=message,
    )


def _root_bootstrap_check(result: RootBootstrapResult) -> BootstrapCheck:
    return _check(
        "root_bootstrap",
        RuntimeValueKind.OPERATOR_MANAGED,
        not result.can_start,
        result.message,
    )


def _admin_bootstrap_values(
    env: Mapping[str, str],
) -> tuple[str, str, str] | RootBootstrapResult:
    try:
        resolved = resolved_runtime_env_settings(env)
    except ValueError as exc:
        return RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            str(exc),
        )

    missing = [
        name
        for name in (
            ADMIN_USERNAME_VAR,
            ADMIN_EMAIL_VAR,
            ADMIN_PASSWORD_VAR,
        )
        if not resolved.get(name)
    ]
    if missing:
        return RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            "Admin bootstrap requires SATOIDC_ADMIN_USERNAME, "
            "SATOIDC_ADMIN_EMAIL, and SATOIDC_ADMIN_PASSWORD.",
        )

    username = resolved[ADMIN_USERNAME_VAR].strip().lower()
    email = resolved[ADMIN_EMAIL_VAR].strip().lower()
    password = resolved[ADMIN_PASSWORD_VAR]

    if not is_valid_login(username):
        return RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            "SATOIDC_ADMIN_USERNAME must be 6-30 lowercase letters and "
            "digits.",
        )
    if not is_valid_email(email):
        return RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            "SATOIDC_ADMIN_EMAIL must be a valid email address.",
        )
    if not is_valid_password(password):
        return RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            "SATOIDC_ADMIN_PASSWORD does not meet the password policy.",
        )

    return username, email, password


def _generated_secret_placeholders(env: Mapping[str, str]) -> list[str]:
    placeholders: list[str] = []
    for name in GENERATED_SECRET_NAMES:
        if is_placeholder_secret(_env_value(env, name)):
            placeholders.append(name)
    return placeholders


def _has_absolute_generated_secret_path(env: Mapping[str, str]) -> bool:
    path = _env_value(env, GENERATED_SECRETS_PATH)
    return bool(path and os.path.isabs(path))


def _generated_secrets_path(env: Mapping[str, str]) -> Path | None:
    path = _env_value(env, GENERATED_SECRETS_PATH)
    if not path or not os.path.isabs(path):
        return None
    return Path(path)


def load_persisted_generated_secrets(
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    values = os.environ if env is None else env
    path = _generated_secrets_path(values)
    if path is None or not path.exists():
        return {}

    persisted: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("export "):
            continue
        key, separator, value = line.removeprefix("export ").partition("=")
        if separator and key in GENERATED_SECRET_NAMES:
            parsed = shlex.split(f"{key}={value}", posix=True)
            if parsed:
                persisted[key] = parsed[0].split("=", 1)[1]
    return persisted


def env_with_persisted_generated_secrets(
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    values = dict(os.environ if env is None else env)
    for name, secret in load_persisted_generated_secrets(values).items():
        if is_placeholder_secret(values.get(name)):
            values[name] = secret
    return values


def persist_generated_secrets(
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    values = dict(os.environ if env is None else env)
    path = _generated_secrets_path(values)
    if path is None:
        return {}

    persisted = load_persisted_generated_secrets(values)
    generated = dict(persisted)
    for name in _generated_secret_placeholders(values):
        if is_placeholder_secret(generated.get(name)):
            generated[name] = secrets.token_urlsafe(64)

    if generated == persisted:
        return generated

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"export {name}={shlex.quote(generated[name])}"
        for name in GENERATED_SECRET_NAMES
        if name in generated
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return generated


def validate_bootstrap_environment(
    env: Mapping[str, str] | None = None,
) -> BootstrapReport:
    values = os.environ if env is None else env
    app_env = _env_value(values, "APP_ENV", "development") or "development"
    is_production = is_production_environment(app_env)
    checks: list[BootstrapCheck] = []

    issuer = _env_value(values, "OAUTH2_JWT_ISS", "http://localhost:8000")
    checks.append(
        _check(
            "OAUTH2_JWT_ISS",
            RuntimeValueKind.OPERATOR_MANAGED,
            is_production and is_operator_issuer_missing(issuer),
            "OAUTH2_JWT_ISS must be set to the public issuer URL in the "
            "deployment platform.",
        )
    )

    jwt_secret = _env_value(values, "OAUTH2_JWT_SECRET_KEY")
    checks.append(
        _check(
            "OAUTH2_JWT_SECRET_KEY",
            RuntimeValueKind.GENERATED,
            is_production and is_placeholder_secret(jwt_secret),
            "OAUTH2_JWT_SECRET_KEY must be generated or configured before "
            "production startup.",
        )
    )

    session_secret = _env_value(values, "SESSION_MIDDLEWARE_SECRET_KEY")
    checks.append(
        _check(
            "SESSION_MIDDLEWARE_SECRET_KEY",
            RuntimeValueKind.GENERATED,
            is_production and is_placeholder_secret(session_secret),
            "SESSION_MIDDLEWARE_SECRET_KEY must be generated or configured "
            "before production startup.",
        )
    )

    generated_placeholders = _generated_secret_placeholders(values)
    checks.append(
        _check(
            GENERATED_SECRETS_PATH,
            RuntimeValueKind.GENERATED,
            is_production
            and bool(generated_placeholders)
            and not _has_absolute_generated_secret_path(values),
            f"{GENERATED_SECRETS_PATH} must be set to an absolute file path "
            "before bootstrap can persist generated secrets.",
        )
    )

    cookie_secure = (_env_value(values, "SESSION_COOKIE_HTTPS_ONLY") or "")
    checks.append(
        _check(
            "SESSION_COOKIE_HTTPS_ONLY",
            RuntimeValueKind.OPERATOR_MANAGED,
            is_production and cookie_secure.lower() in {"", "0", "false"},
            "SESSION_COOKIE_HTTPS_ONLY must be enabled in production.",
        )
    )

    database_url = _env_value(
        values, "DATABASE_URL", DEFAULT_DATABASE_URL
    ) or DEFAULT_DATABASE_URL
    sync_database_url = _env_value(
        values, "SYNC_DATABASE_URL", DEFAULT_SYNC_DATABASE_URL
    ) or DEFAULT_SYNC_DATABASE_URL
    database_blocked = False
    try:
        validate_database_url_pair(database_url, sync_database_url)
    except ValueError:
        database_blocked = True
    checks.append(
        _check(
            "DATABASE_URL/SYNC_DATABASE_URL",
            RuntimeValueKind.OPERATOR_MANAGED,
            database_blocked,
            "DATABASE_URL and SYNC_DATABASE_URL must target the same "
            "physical database.",
        )
    )

    return BootstrapReport(tuple(checks))


async def check_root_user_ready() -> BootstrapCheck:
    from setup_wizard.get_root import exists_root_user  # noqa: PLC0415

    try:
        root_exists = await exists_root_user()
    except Exception:
        return _check(
            "root_permission",
            RuntimeValueKind.OPERATOR_MANAGED,
            True,
            "Root-user readiness check failed. Verify migrations and "
            "database connectivity before starting SatOIDC.",
        )

    return _check(
        "root_permission",
        RuntimeValueKind.OPERATOR_MANAGED,
        not root_exists,
        "A root permission must exist before SatOIDC starts.",
    )


async def _root_or_admin_permission_exists(session) -> bool:
    permission = await session.scalar(
        select(Permission.id).where(
            Permission.permission_type.in_(
                (PermissionsEnum.ROOT, PermissionsEnum.ADMIN)
            )
        )
    )
    return permission is not None


async def _bootstrap_identity_exists(
    session, *, username: str, email: str
) -> bool:
    user = await session.scalar(
        select(User.id).where((User.login == username) | (User.email == email))
    )
    return user is not None


async def bootstrap_root_user_from_env(
    env: Mapping[str, str] | None = None,
) -> RootBootstrapResult:
    from setup_wizard.get_root import setup_session  # noqa: PLC0415

    values = os.environ if env is None else env
    try:
        async with setup_session() as session:
            if await _root_or_admin_permission_exists(session):
                result = RootBootstrapResult(
                    RootBootstrapStatus.SKIPPED_EXISTING_ADMIN,
                    "Root bootstrap skipped because a root/admin permission "
                    "already exists.",
                )
                LOGGER.info(
                    "Root bootstrap skipped",
                    extra={
                        "event_name": "setup.root_bootstrap_skipped",
                        "component": "setup_bootstrap",
                        "reason": "existing_admin",
                    },
                )
                return result

            bootstrap_values = _admin_bootstrap_values(values)
            if isinstance(bootstrap_values, RootBootstrapResult):
                LOGGER.info(
                    "Root bootstrap blocked",
                    extra={
                        "event_name": "setup.root_bootstrap_blocked",
                        "component": "setup_bootstrap",
                        "reason": bootstrap_values.message,
                    },
                )
                return bootstrap_values

            username, email, password = bootstrap_values
            if await _bootstrap_identity_exists(
                session, username=username, email=email
            ):
                result = RootBootstrapResult(
                    RootBootstrapStatus.BLOCKED,
                    "Root bootstrap cannot reuse an existing username or "
                    "email.",
                )
                LOGGER.info(
                    "Root bootstrap blocked",
                    extra={
                        "event_name": "setup.root_bootstrap_blocked",
                        "component": "setup_bootstrap",
                        "reason": "identity_conflict",
                    },
                )
                return result

            user = User(
                lnurl_pubkey=None,
                email=email,
                login=username,
                password_hash=hash_password(password),
                nickname=username,
                is_active=True,
                email_verified=True,
            )
            session.add(user)
            await session.flush()
            session.add(
                Permission(
                    user_id=user.id,
                    granted_by=None,
                    permission_type=PermissionsEnum.ROOT,
                    expiration_date=None,
                    reason="Initial root bootstrap from environment",
                )
            )
            await session.commit()

            result = RootBootstrapResult(
                RootBootstrapStatus.CREATED,
                "Root user bootstrapped from environment.",
                user_id=str(user.id),
            )
            LOGGER.info(
                "Root bootstrap created initial root user",
                extra={
                    "event_name": "setup.root_bootstrap_created",
                    "component": "setup_bootstrap",
                    "user_id": str(user.id),
                    "username": username,
                    "email": email,
                    "password_source": (
                        "_FILE"
                        if f"{ADMIN_PASSWORD_VAR}_FILE"
                        in _normalized_env(values)
                        and ADMIN_PASSWORD_VAR not in _normalized_env(values)
                        else "env"
                    ),
                },
            )
            return result
    except Exception:
        result = RootBootstrapResult(
            RootBootstrapStatus.BLOCKED,
            "Root bootstrap failed. Verify migrations and database "
            "connectivity before starting SatOIDC.",
        )
        LOGGER.info(
            "Root bootstrap failed",
            extra={
                "event_name": "setup.root_bootstrap_failed",
                "component": "setup_bootstrap",
            },
        )
        return result


def check_oidc_signing_ready() -> BootstrapCheck:
    from satoidc.auth.oidc_keys import (  # noqa: PLC0415
        ensure_active_signing_key,
    )

    try:
        ensure_active_signing_key()
    except Exception:
        return _check(
            "oidc_signing_key",
            RuntimeValueKind.OPERATOR_MANAGED,
            True,
            "OIDC signing-key readiness check failed. Verify migrations, "
            "database connectivity, and signing secret configuration.",
        )

    return _check(
        "oidc_signing_key",
        RuntimeValueKind.OPERATOR_MANAGED,
        False,
        "OIDC signing-key readiness check passed.",
    )


async def check_database_ready(database_url: str) -> BootstrapCheck:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception:
        return _check(
            "DATABASE_URL",
            RuntimeValueKind.OPERATOR_MANAGED,
            True,
            "Database readiness check failed. Verify database service "
            "health, network reachability, credentials, and DATABASE_URL.",
        )
    finally:
        await engine.dispose()

    return _check(
        "DATABASE_URL",
        RuntimeValueKind.OPERATOR_MANAGED,
        False,
        "Database readiness check passed.",
    )


async def build_database_state_report(
    database_url: str, env: Mapping[str, str] | None = None
) -> BootstrapReport:
    database_check = await check_database_ready(database_url)
    if database_check.status == BootstrapStatus.BLOCKED:
        return BootstrapReport(
            (
                database_check,
                _check(
                    "root_bootstrap",
                    RuntimeValueKind.OPERATOR_MANAGED,
                    True,
                    "Root bootstrap was not attempted because the database "
                    "readiness check failed.",
                ),
            )
        )

    root_bootstrap = await bootstrap_root_user_from_env(env)
    return BootstrapReport(
        (
            database_check,
            _root_bootstrap_check(root_bootstrap),
            await check_root_user_ready(),
            check_oidc_signing_ready(),
        )
    )


def _print_blocking_report(report: BootstrapReport) -> None:
    print("Bootstrap configuration is incomplete:")
    for message in report.blocking_messages:
        print(f"- {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-state",
        action="store_true",
        help="Include database-backed root and OIDC signing readiness checks.",
    )
    args = parser.parse_args()

    env = env_with_persisted_generated_secrets()
    report = validate_bootstrap_environment(env)
    if not report.can_start and _has_absolute_generated_secret_path(env):
        persist_generated_secrets(env)
        env = env_with_persisted_generated_secrets(env)
        report = validate_bootstrap_environment(env)

    if report.can_start:
        for name in GENERATED_SECRET_NAMES:
            if name in env:
                os.environ[name] = env[name]
        database_url = env.get("DATABASE_URL", DEFAULT_DATABASE_URL)
        database_report = (
            asyncio.run(build_database_state_report(database_url, env))
            if args.database_state
            else BootstrapReport(
                (asyncio.run(check_database_ready(database_url)),)
            )
        )
        report = _combine_reports(report, database_report)

    if report.can_start:
        print("Bootstrap configuration checks passed.")
        return 0

    _print_blocking_report(report)
    return 1


if __name__ == "__main__":
    sys.exit(main())
