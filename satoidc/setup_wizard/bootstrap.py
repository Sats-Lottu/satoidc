from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import shlex
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from satoidc.runtime_config import (
    is_operator_issuer_missing,
    is_placeholder_secret,
    is_production_environment,
    validate_database_url_pair,
)

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///satoidc.db"
DEFAULT_SYNC_DATABASE_URL = "sqlite:///satoidc.db"
GENERATED_SECRETS_PATH = "SETUP_GENERATED_SECRETS_PATH"
GENERATED_SECRET_NAMES = (
    "OAUTH2_JWT_SECRET_KEY",
    "SESSION_MIDDLEWARE_SECRET_KEY",
)


class RuntimeValueKind(str, Enum):
    GENERATED = "generated"
    OPERATOR_MANAGED = "operator-managed"
    OPTIONAL = "optional"


class BootstrapStatus(str, Enum):
    OK = "ok"
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


async def build_database_state_report(database_url: str) -> BootstrapReport:
    return BootstrapReport(
        (
            await check_database_ready(database_url),
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
            asyncio.run(build_database_state_report(database_url))
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
