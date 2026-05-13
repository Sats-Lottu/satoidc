from http import HTTPStatus

from satoidc.auth.oauth2 import generate_user_info
from satoidc.models import User
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
    assert claims["name"] == "Satoshi"
    assert claims["lnurl_pubkey"] == "wallet-key"
