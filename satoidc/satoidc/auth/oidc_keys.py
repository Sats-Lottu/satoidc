import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from satoidc.auth.oidc_signing_backends import get_signing_backend
from satoidc.models import OidcSigningKey, OidcSigningKeyAuditEvent
from satoidc.models import database as database_module
from satoidc.settings import ENV

log = logging.getLogger(__name__)

PUBLISHABLE_KEY_STATUSES = {"active", "validating"}


def _now() -> datetime:
    return datetime.now(UTC)


def _retired_after(rotated_at: datetime) -> datetime:
    retention_seconds = (
        ENV.OAUTH2_TOKEN_EXPIRES_IN
        + ENV.OIDC_JWKS_CACHE_TTL_SECONDS
        + ENV.OIDC_KEY_RETENTION_MARGIN_SECONDS
    )
    return rotated_at + timedelta(seconds=retention_seconds)


def _audit(
    session: Session,
    event: str,
    kid: str,
    actor: str = "system",
) -> None:
    session.add(
        OidcSigningKeyAuditEvent(event=event, kid=kid, actor=actor)
    )


def _generate_key_row(
    status: str = "validating",
    *,
    rotate_backend_key: bool = False,
) -> OidcSigningKey:
    return get_signing_backend().create_key_row(
        status=status,
        rotate_backend_key=rotate_backend_key,
    )


def _session() -> Session:
    return database_module.db()


def _matches_current_backend(key: OidcSigningKey) -> bool:
    backend_reference = key.backend_reference or "database"
    backend = get_signing_backend()
    if backend.backend_reference == "database":
        return backend_reference == "database"
    return backend_reference.startswith(f"{backend.backend_reference}:")


def create_signing_key(
    *,
    status: str = "validating",
    actor: str = "system",
    rotate_backend_key: bool = False,
) -> OidcSigningKey:
    session = _session()
    key = _generate_key_row(
        status=status,
        rotate_backend_key=rotate_backend_key,
    )
    if status == "active":
        key.activated_at = _now()
    session.add(key)
    _audit(session, "key.created", key.kid, actor)
    if status == "active":
        _audit(session, "key.activated", key.kid, actor)
    session.commit()
    session.refresh(key)
    return key


def ensure_active_signing_key() -> OidcSigningKey:
    session = _session()
    active_keys = session.scalars(
        select(OidcSigningKey).where(OidcSigningKey.status == "active")
    ).all()
    for active in active_keys:
        if _matches_current_backend(active):
            return active
    if active_keys:
        for active in active_keys:
            active.status = "validating"
            active.validating_since = _now()
            active.retired_after = _retired_after(active.validating_since)
            _audit(session, "key.demoted_to_validating", active.kid)
        session.commit()
    return create_signing_key(status="active")


def get_active_jwt_config() -> dict[str, Any]:
    key_row: OidcSigningKey | None = None
    try:
        key_row = ensure_active_signing_key()
        return get_signing_backend().jwt_config(key_row)
    except Exception as exc:
        log.error(
            "OIDC signing configuration failed",
            extra={
                "event_name": "oidc.signing_config_failed",
                "component": "oidc_keys",
                "outcome": "failed",
                "reason": exc.__class__.__name__,
                "kid": key_row.kid if key_row else None,
            },
        )
        raise


def audit_token_signed(kid: str) -> None:
    session = _session()
    _audit(session, "token.signed", kid)
    session.commit()
    log.info("OIDC token signed", extra={"kid": kid})


def get_jwks() -> dict[str, list[dict[str, Any]]]:
    ensure_active_signing_key()
    session = _session()
    keys = session.scalars(
        select(OidcSigningKey)
        .where(OidcSigningKey.status.in_(PUBLISHABLE_KEY_STATUSES))
        .order_by(OidcSigningKey.created_at)
    ).all()
    return {"keys": [json.loads(key.public_jwk) for key in keys]}


def activate_signing_key(kid: str, *, actor: str = "system") -> OidcSigningKey:
    session = _session()
    now = _now()
    key = session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == kid)
    )
    if key is None:
        raise ValueError(f"Unknown OIDC signing key: {kid}")
    if key.status == "retired":
        raise ValueError("Retired OIDC signing keys cannot be activated")

    active_keys = session.scalars(
        select(OidcSigningKey).where(OidcSigningKey.status == "active")
    ).all()
    for active in active_keys:
        if active.kid == key.kid:
            continue
        active.status = "validating"
        active.validating_since = now
        active.retired_after = _retired_after(now)
        _audit(session, "key.demoted_to_validating", active.kid, actor)

    key.status = "active"
    key.activated_at = now
    key.validating_since = None
    key.retired_after = None
    key.retired_at = None
    _audit(session, "key.activated", key.kid, actor)
    session.commit()
    session.refresh(key)
    return key


def rotate_signing_key(*, actor: str = "system") -> OidcSigningKey:
    new_key = create_signing_key(actor=actor, rotate_backend_key=True)
    return activate_signing_key(new_key.kid, actor=actor)


def retire_expired_signing_keys(*, actor: str = "system") -> int:
    session = _session()
    now = _now()
    expired_keys = session.scalars(
        select(OidcSigningKey).where(
            OidcSigningKey.status == "validating",
            OidcSigningKey.retired_after.is_not(None),
            OidcSigningKey.retired_after < now,
        )
    ).all()
    for key in expired_keys:
        key.status = "retired"
        key.retired_at = now
        _audit(session, "key.retired", key.kid, actor)
    session.commit()
    return len(expired_keys)


def list_signing_keys() -> list[OidcSigningKey]:
    ensure_active_signing_key()
    session = _session()
    return list(
        session.scalars(
            select(OidcSigningKey).order_by(OidcSigningKey.created_at)
        ).all()
    )
