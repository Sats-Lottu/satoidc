"""OIDC server example"""

import time
from contextvars import ContextVar
from secrets import token_urlsafe

from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator,
    create_query_client_func,
    create_revocation_endpoint,
    create_save_token_func,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import (
    IntrospectionEndpoint as _IntrospectionEndpoint,
)
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core.grants.util import create_half_hash

from satoidc.auth.client_management import is_client_disabled
from satoidc.auth.oidc_keys import (
    audit_token_signed,
    ensure_active_signing_key,
    get_active_jwt_config,
)
from satoidc.auth.oidc_signing_backends import get_signing_backend
from satoidc.fastapi_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from satoidc.models import (
    OAuth2AuthorizationCode,
    OAuth2Client,
    OAuth2Token,
    User,
)
from satoidc.models.database import db
from satoidc.settings import ENV

_oidc_jwt_config = ContextVar("oidc_jwt_config", default=None)


def _current_oidc_jwt_config():
    jwt_config = _oidc_jwt_config.get()
    if jwt_config is None:
        return get_active_jwt_config()
    return jwt_config


def exists_nonce(nonce, req):
    """Check nonce existence."""
    exists = (
        db.query(OAuth2AuthorizationCode)
        .filter(
            OAuth2AuthorizationCode.client_id == req.payload.client_id,
            OAuth2AuthorizationCode.nonce == nonce,
        )
        .first()
    )
    return bool(exists)


def generate_user_info(user, scope):
    """Generates the user profile information"""
    user_info = UserInfo(sub=str(user.id))
    if "email" in scope:
        user_info["email"] = user.email
        user_info["email_verified"] = bool(
            getattr(user, "email_verified", False)
        )
    if "profile" in scope:
        user_info["name"] = user.nickname
        user_info["lnurl_pubkey"] = user.lnurl_pubkey
    return user_info


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """AuthorizationCodeGrant class"""

    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def generate_authorization_code(self):  # noqa: PLR6301
        return token_urlsafe(64)

    def save_authorization_code(self, code, request):
        nonce = request.payload.data.get("nonce")
        code_challenge = request.payload.data.get("code_challenge")
        code_challenge_method = request.payload.data.get(
            "code_challenge_method"
        )
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=self.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.payload.scope,
            user_id=request.user.id,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.add(auth_code)
        db.commit()
        return auth_code

    def query_authorization_code(self, code, client):  # noqa: PLR6301
        """Query the authorization code"""
        item = (
            db.query(OAuth2AuthorizationCode)
            .filter(
                OAuth2AuthorizationCode.code == code,
                OAuth2AuthorizationCode.client_id == client.client_id,
            )
            .first()
        )
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):  # noqa: PLR6301
        db.delete(authorization_code)
        db.commit()

    def authenticate_user(self, authorization_code):  # noqa: PLR6301
        return (
            db.query(User)
            .filter(User.id == authorization_code.user_id)
            .first()
        )


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """RefreshTokenGrant class"""

    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def authenticate_refresh_token(self, refresh_token):  # noqa: PLR6301
        token = (
            db.query(OAuth2Token)
            .filter(OAuth2Token.refresh_token == refresh_token)
            .first()
        )
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):  # noqa: PLR6301
        return db.query(User).filter(User.id == credential.user_id).first()

    def revoke_old_credential(self, credential):  # noqa: PLR6301
        credential.refresh_token_revoked_at = int(time.time())
        db.add(credential)
        db.commit()


class IntrospectionEndpoint(_IntrospectionEndpoint):
    """IntrospectionEndpoint class"""

    def query_token(self, token, token_type_hint):  # noqa: PLR6301
        if token_type_hint == "access_token":
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.access_token == token)
                .first()
            )
        elif token_type_hint == "refresh_token":
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.refresh_token == token)
                .first()
            )
        else:
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.access_token == token)
                .first()
            )
            if not tok:
                tok = (
                    db.query(OAuth2Token)
                    .filter(OAuth2Token.refresh_token == token)
                    .first()
                )
        return tok

    def check_permission(self, token, client, request):  # noqa: PLR6301
        return token.check_client(client)

    def introspect_token(self, token):  # noqa: PLR6301
        expires_at = token.issued_at + token.expires_in
        return {
            "active": True,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "username": str(token.user_id),
            "scope": token.get_scope(),
            "sub": str(token.user_id),
            "aud": token.client_id,
            "iss": ENV.OAUTH2_JWT_ISS,
            "exp": expires_at,
            "iat": token.issued_at,
        }


class OpenIDCode(_OpenIDCode):
    """OpenIDCode class"""

    def exists_nonce(self, nonce, request):  # noqa: PLR6301
        return exists_nonce(nonce, request)

    def resolve_client_private_key(self, client):  # noqa: PLR6301
        return _current_oidc_jwt_config()["key"]

    def get_client_algorithm(self, client):  # noqa: PLR6301
        return _current_oidc_jwt_config()["alg"]

    def get_client_claims(self, client):  # noqa: PLR6301
        jwt_config = _current_oidc_jwt_config()
        now = int(time.time())
        return {
            "iss": jwt_config["iss"],
            "aud": [client.get_client_id()],
            "iat": now,
            "exp": now + jwt_config["exp"],
            "auth_time": now,
        }

    def get_encode_header(self, client):  # noqa: PLR6301
        jwt_config = _current_oidc_jwt_config()
        return {
            "alg": jwt_config["alg"],
            "typ": "JWT",
            "kid": jwt_config["kid"],
        }

    def generate_user_info(self, user, scope):  # noqa: PLR6301
        return generate_user_info(user, scope)

    def encode_id_token(self, token, request):
        key_row = ensure_active_signing_key()
        jwt_config = get_active_jwt_config()
        context_token = _oidc_jwt_config.set(jwt_config)
        try:
            if jwt_config["key"] is not None:
                id_token = super().encode_id_token(token, request)
            else:
                id_token = self._encode_external_id_token(
                    token, request, jwt_config, key_row
                )
            audit_token_signed(jwt_config["kid"])
            return id_token
        finally:
            _oidc_jwt_config.reset(context_token)

    def _encode_external_id_token(
        self,
        token,
        request,
        jwt_config,
        key_row,
    ):
        header = self.get_encode_header(request.client)
        claims = self.get_compatible_claims(request)
        if request.authorization_code:
            claims.update(
                self.get_authorization_code_claims(request.authorization_code)
            )
        access_token = token.get("access_token")
        if access_token:
            at_hash = create_half_hash(access_token, jwt_config["alg"])
            if at_hash is not None:
                claims["at_hash"] = at_hash.decode("utf-8")
        claims.update(self.generate_user_info(request.user, token["scope"]))
        return get_signing_backend().encode_jwt(header, claims, key_row)


authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app):
    """Setup the application configuration"""
    base_query_client = create_query_client_func(db, OAuth2Client)

    def query_client(client_id):
        client = base_query_client(client_id)
        if client and is_client_disabled(client):
            return None
        return client

    save_token = create_save_token_func(db, OAuth2Token)
    authorization.init_app(
        app, query_client=query_client, save_token=save_token
    )

    # Support authorization code + PKCE. Other OIDC response types should only
    # be registered when discovery and tests explicitly advertise them.
    authorization.register_grant(
        AuthorizationCodeGrant,
        [OpenIDCode(require_nonce=True), CodeChallenge(required=True)],
    )
    authorization.register_grant(RefreshTokenGrant)
    authorization.register_endpoint(IntrospectionEndpoint)

    # revocation
    revocation_cls = create_revocation_endpoint(db, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
