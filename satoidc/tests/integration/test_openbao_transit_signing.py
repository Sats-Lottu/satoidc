import json
from types import SimpleNamespace

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

import satoidc.auth.oidc_signing_backends as signing_backends_module
from satoidc.auth.oauth2 import OpenIDCode
from satoidc.auth.oidc_keys import create_signing_key

pytestmark = [pytest.mark.integration, pytest.mark.container]

OPENBAO_TOKEN = "test-root-token"


class Client:
    @staticmethod
    def get_client_id():
        return "client-1"


async def test_openbao_transit_signs_id_token(
    monkeypatch: pytest.MonkeyPatch,
    db_session,
    make_user,
    openbao_addr: str,
) -> None:
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_SIGNING_BACKEND", "transit"
    )
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_TRANSIT_ADDR", openbao_addr
    )
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_TRANSIT_TOKEN", OPENBAO_TOKEN
    )
    monkeypatch.setattr(
        signing_backends_module.ENV,
        "OIDC_TRANSIT_KEY_NAME",
        "satoidc-integration",
    )

    user = await make_user()
    active_key = create_signing_key(status="active")
    request = SimpleNamespace(
        client=Client(),
        authorization_code=None,
        user=user,
    )

    id_token = OpenIDCode(require_nonce=True).encode_id_token(
        {"scope": "openid profile", "access_token": "access-token"},
        request,
    )
    decoded = jwt.decode(
        id_token,
        RSAKey.import_key(json.loads(active_key.public_jwk)),
        [active_key.alg],
    )

    assert decoded.header["kid"] == "satoidc-integration-v1"
    assert decoded.claims["sub"] == str(user.id)
    assert active_key.backend_reference == "transit:satoidc-integration:1"
    assert not active_key.private_jwk_encrypted


async def test_openbao_transit_signs_ps384_id_token(
    monkeypatch: pytest.MonkeyPatch,
    db_session,
    make_user,
    openbao_addr: str,
) -> None:
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_SIGNING_BACKEND", "transit"
    )
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_TRANSIT_ADDR", openbao_addr
    )
    monkeypatch.setattr(
        signing_backends_module.ENV, "OIDC_TRANSIT_TOKEN", OPENBAO_TOKEN
    )
    monkeypatch.setattr(
        signing_backends_module.ENV,
        "OIDC_TRANSIT_KEY_NAME",
        "satoidc-integration-ps384",
    )
    monkeypatch.setattr(
        signing_backends_module.ENV,
        "OAUTH2_JWT_ALG",
        "PS384",
    )

    user = await make_user(
        login="ps384_user",
        email="ps384@example.com",
    )
    active_key = create_signing_key(status="active")
    request = SimpleNamespace(
        client=Client(),
        authorization_code=None,
        user=user,
    )

    id_token = OpenIDCode(require_nonce=True).encode_id_token(
        {"scope": "openid profile", "access_token": "access-token"},
        request,
    )
    decoded = jwt.decode(
        id_token,
        RSAKey.import_key(json.loads(active_key.public_jwk)),
        ["PS384"],
    )

    assert decoded.header["alg"] == "PS384"
    assert decoded.header["kid"] == "satoidc-integration-ps384-v1"
    assert decoded.claims["sub"] == str(user.id)
    assert active_key.alg == "PS384"
