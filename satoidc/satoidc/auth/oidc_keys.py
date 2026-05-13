import base64
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet
from joserfc import jwk
from sqlalchemy import select
from sqlalchemy.orm import Session

from satoidc.models import OidcSigningKey, OidcSigningKeyAuditEvent
from satoidc.models import database as database_module
from satoidc.settings import ENV

log = logging.getLogger(__name__)

PUBLISHABLE_KEY_STATUSES = {"active", "validating"}


def _now() -> datetime:
    return datetime.now(UTC)


def _fernet() -> Fernet:
    digest = hashlib.sha256(ENV.OAUTH2_JWT_SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt_private_jwk(private_jwk: dict[str, Any]) -> str:
    payload = json.dumps(private_jwk, sort_keys=True).encode()
    return _fernet().encrypt(payload).decode()


def _decrypt_private_jwk(encrypted_private_jwk: str) -> dict[str, Any]:
    payload = _fernet().decrypt(encrypted_private_jwk.encode())
    return json.loads(payload)


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


def _generate_key_row(status: str = "validating") -> OidcSigningKey:
    key = jwk.generate_key("RSA", 2048, private=True, auto_kid=True)
    private_jwk = key.as_dict(private=True)
    public_jwk = key.as_dict(private=False)
    public_jwk["alg"] = ENV.OAUTH2_JWT_ALG
    public_jwk["use"] = "sig"
    kid = public_jwk["kid"]
    return OidcSigningKey(
        kid=kid,
        alg=ENV.OAUTH2_JWT_ALG,
        kty="RSA",
        use="sig",
        status=status,
        public_jwk=json.dumps(public_jwk, sort_keys=True),
        private_jwk_encrypted=_encrypt_private_jwk(private_jwk),
    )


def _session() -> Session:
    return database_module.db()


def create_signing_key(
    *,
    status: str = "validating",
    actor: str = "system",
) -> OidcSigningKey:
    session = _session()
    key = _generate_key_row(status=status)
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
    active = session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.status == "active")
    )
    if active:
        return active
    return create_signing_key(status="active")


def get_active_jwt_config() -> dict[str, Any]:
    key_row = ensure_active_signing_key()
    private_jwk = _decrypt_private_jwk(key_row.private_jwk_encrypted)
    return {
        "key": jwk.import_key(private_jwk),
        "kid": key_row.kid,
        "alg": key_row.alg,
        "iss": ENV.OAUTH2_JWT_ISS,
        "exp": ENV.OAUTH2_TOKEN_EXPIRES_IN,
    }


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
    new_key = create_signing_key(actor=actor)
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
