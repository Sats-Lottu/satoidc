import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from satoidc.auth.oauth2 import OpenIDCode
from satoidc.auth.oidc_keys import (
    activate_signing_key,
    create_signing_key,
    get_active_jwt_config,
    get_jwks,
    list_signing_keys,
    retire_expired_signing_keys,
    rotate_signing_key,
)
from satoidc.models import OidcSigningKey, OidcSigningKeyAuditEvent


def _jwt_header(token: bytes | str) -> dict:
    if isinstance(token, bytes):
        token = token.decode()
    encoded_header = token.split(".", 1)[0]
    padding = "=" * (-len(encoded_header) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded_header + padding))


class Client:
    @staticmethod
    def get_client_id():
        return "client-1"


async def test_jwks_bootstraps_persistent_active_key(db_session):
    jwks = get_jwks()
    key = jwks["keys"][0]

    stored_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == key["kid"])
    )

    assert stored_key is not None
    assert stored_key.status == "active"
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    for private_member in ("d", "p", "q", "dp", "dq", "qi"):
        assert private_member not in key


async def test_rotation_keeps_previous_key_publishable(db_session):
    original_kid = get_jwks()["keys"][0]["kid"]

    rotated = rotate_signing_key()
    jwks_kids = {key["kid"] for key in get_jwks()["keys"]}
    original_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == original_kid)
    )

    assert rotated.kid != original_kid
    assert jwks_kids == {original_kid, rotated.kid}
    assert original_key.status == "validating"
    assert original_key.retired_after is not None


async def test_activate_signing_key_allows_only_one_active_key(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    second_key = create_signing_key()

    activated = activate_signing_key(second_key.kid)
    active_keys = (
        await db_session.scalars(
            select(OidcSigningKey).where(OidcSigningKey.status == "active")
        )
    ).all()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )

    assert activated.kid == second_key.kid
    assert [key.kid for key in active_keys] == [second_key.kid]
    assert first_key.status == "validating"


async def test_activate_current_active_key_keeps_it_active(db_session):
    active_kid = get_jwks()["keys"][0]["kid"]

    activated = activate_signing_key(active_kid)
    active_keys = (
        await db_session.scalars(
            select(OidcSigningKey).where(OidcSigningKey.status == "active")
        )
    ).all()

    assert activated.kid == active_kid
    assert [key.kid for key in active_keys] == [active_kid]


async def test_activate_signing_key_rejects_unknown_or_retired_key(
    db_session,
):
    retired_key = create_signing_key(status="retired")

    with pytest.raises(
        ValueError, match="Unknown OIDC signing key: missing-kid"
    ):
        activate_signing_key("missing-kid")

    with pytest.raises(
        ValueError, match="Retired OIDC signing keys cannot be activated"
    ):
        activate_signing_key(retired_key.kid)


async def test_retire_expired_keys_removes_them_from_jwks(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    rotate_signing_key()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )
    first_key.retired_after = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    retired_count = retire_expired_signing_keys()
    jwks_kids = {key["kid"] for key in get_jwks()["keys"]}
    await db_session.refresh(first_key)

    assert retired_count == 1
    assert first_key.status == "retired"
    assert first_kid not in jwks_kids


async def test_retire_expired_signing_keys_ignores_unexpired_keys(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    rotate_signing_key()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )

    retired_count = retire_expired_signing_keys()
    await db_session.refresh(first_key)

    assert retired_count == 0
    assert first_key.status == "validating"


async def test_active_jwt_config_and_key_listing_use_persisted_key(db_session):
    config = get_active_jwt_config()
    keys = list_signing_keys()

    assert config["kid"] == keys[0].kid
    assert config["alg"] == "RS256"
    assert config["iss"]
    assert config["exp"] > 0
    assert keys[0].status == "active"


def test_active_jwt_config_logs_sanitized_decrypt_failure(
    monkeypatch, caplog
):
    get_jwks()
    caplog.set_level(logging.ERROR, logger="satoidc.auth.oidc_keys")

    def fail_decrypt(encrypted_private_jwk):
        raise RuntimeError("private-jwk-secret")

    monkeypatch.setattr(
        "satoidc.auth.oidc_keys._decrypt_private_jwk", fail_decrypt
    )

    with pytest.raises(RuntimeError, match="private-jwk-secret"):
        get_active_jwt_config()

    assert any(
        record.event_name == "oidc.signing_config_failed"
        and record.component == "oidc_keys"
        and record.reason == "RuntimeError"
        for record in caplog.records
    )
    assert "private-jwk-secret" not in caplog.text


async def test_id_token_uses_active_kid_and_audits_signature(
    db_session, make_user
):
    user = await make_user()
    active_kid = get_jwks()["keys"][0]["kid"]
    request = SimpleNamespace(
        client=Client(),
        authorization_code=None,
        user=user,
    )

    id_token = OpenIDCode(require_nonce=True).encode_id_token(
        {"scope": "openid profile", "access_token": "access-token"},
        request,
    )
    header = _jwt_header(id_token)
    audit_event = await db_session.scalar(
        select(OidcSigningKeyAuditEvent).where(
            OidcSigningKeyAuditEvent.event == "token.signed",
            OidcSigningKeyAuditEvent.kid == active_kid,
        )
    )

    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == active_kid
    assert audit_event is not None
