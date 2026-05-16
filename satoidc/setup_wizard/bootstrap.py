from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from satoidc.runtime_config import (
    is_operator_issuer_missing,
    is_placeholder_secret,
    is_production_environment,
    validate_database_url_pair,
)

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///satoidc.db"
DEFAULT_SYNC_DATABASE_URL = "sqlite:///satoidc.db"


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


def main() -> int:
    report = validate_bootstrap_environment()
    if report.can_start:
        print("Bootstrap configuration checks passed.")
        return 0

    print("Bootstrap configuration is incomplete:")
    for message in report.blocking_messages:
        print(f"- {message}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
