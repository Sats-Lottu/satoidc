from http import HTTPStatus
from types import SimpleNamespace
from uuid import UUID

import satoidc.auth.oauth2 as oauth2_module
from satoidc.auth.oauth2 import generate_user_info
from satoidc.models import OAuth2Client, User
from satoidc.routes.oauth2 import well_known_root


def test_oidc_discovery_metadata_matches_advertised_contract(app_client):
    response = app_client.get("/.well-known/openid-configuration")

    assert response.status_code == HTTPStatus.OK
    metadata = response.json()
    assert metadata["issuer"] == "http://localhost:8000"
    assert metadata["authorization_endpoint"].endswith("/authorize")
    assert metadata["token_endpoint"].endswith("/oauth/token")
    assert metadata["userinfo_endpoint"].endswith("/oauth/userinfo")
    assert metadata["jwks_uri"].endswith("/.well-known/jwks.json")
    assert metadata["response_types_supported"] == ["code"]
    assert "authorization_code" in metadata["grant_types_supported"]
    assert "refresh_token" in metadata["grant_types_supported"]
    assert metadata["id_token_signing_alg_values_supported"] == ["RS256"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert well_known_root()["issuer"] == metadata["issuer"]


def test_jwks_endpoint_exposes_only_public_key_material(app_client):
    response = app_client.get("/.well-known/jwks.json")

    assert response.status_code == HTTPStatus.OK
    jwks = response.json()
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert "kid" in key
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "n" in key
    assert "e" in key
    for private_member in ("d", "p", "q", "dp", "dq", "qi"):
        assert private_member not in key


def test_userinfo_claims_follow_granted_scopes():
    user = User(
        lnurl_pubkey="wallet-key",
        email="satoshi@example.com",
        login="satoshi1",
        password_hash="hash",
        nickname="Satoshi",
    )

    claims = generate_user_info(user, "openid email profile")

    assert claims["sub"] == str(user.id)
    assert claims["email"] == "satoshi@example.com"
    assert claims["email_verified"] is False
    assert claims["name"] == "Satoshi"
    assert claims["lnurl_pubkey"] == "wallet-key"


def test_config_oauth_filters_disabled_clients(monkeypatch):
    captured = {}
    user_id = UUID("00000000-0000-0000-0000-000000000001")
    enabled_client = OAuth2Client(
        user_id=user_id,
        client_id="enabled-client",
        client_id_issued_at=1,
        client_secret="secret",
    )
    disabled_client = OAuth2Client(
        user_id=user_id,
        client_id="disabled-client",
        client_id_issued_at=1,
        client_secret="secret",
    )
    disabled_client.set_client_metadata({"disabled_at": 123})

    class FakeAuthorization:
        @staticmethod
        def init_app(app, query_client, save_token):
            captured["query_client"] = query_client
            captured["save_token"] = save_token

        @staticmethod
        def register_grant(*args):
            captured.setdefault("grants", []).append(args)

        @staticmethod
        def register_endpoint(endpoint):
            captured.setdefault("endpoints", []).append(endpoint)

    class FakeRequireOAuth:
        @staticmethod
        def register_token_validator(validator):
            captured["validator"] = validator

    def base_query_client(client_id):
        return {
            "enabled-client": enabled_client,
            "disabled-client": disabled_client,
        }.get(client_id)

    monkeypatch.setattr(
        oauth2_module,
        "create_query_client_func",
        lambda db, model: base_query_client,
    )
    monkeypatch.setattr(
        oauth2_module,
        "create_save_token_func",
        lambda db, model: "save-token",
    )
    monkeypatch.setattr(
        oauth2_module,
        "create_revocation_endpoint",
        lambda db, model: "revocation-endpoint",
    )
    monkeypatch.setattr(
        oauth2_module,
        "create_bearer_token_validator",
        lambda db, model: lambda: "bearer-validator",
    )
    monkeypatch.setattr(oauth2_module, "authorization", FakeAuthorization())
    monkeypatch.setattr(oauth2_module, "require_oauth", FakeRequireOAuth())

    oauth2_module.config_oauth(SimpleNamespace(config={}))

    assert captured["query_client"]("enabled-client") is enabled_client
    assert captured["query_client"]("disabled-client") is None
    assert captured["query_client"]("missing-client") is None
    assert captured["save_token"] == "save-token"
    assert captured["validator"] == "bearer-validator"
    assert "revocation-endpoint" in captured["endpoints"]
