import hmac
from typing import Annotated, Literal
from uuid import UUID

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from satoidc.auth.oauth2 import (
    KEY,
    authorization,
    generate_user_info,
    require_oauth,
)
from satoidc.auth.scopes import scopes
from satoidc.models import User
from satoidc.models.database import get_session, remove_sync_session
from satoidc.settings import ENV

router = APIRouter(prefix="/oauth", tags=["OAuth2"])
well_known_router = APIRouter(tags=["OAuth2"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _create_authorization_response_sync(
    request: Request, user: User, decision: str
):
    try:
        grant = authorization.validate_consent_request(
            request=request, end_user=user
        )
        if decision == "deny":
            return authorization.create_authorization_response(
                request=request,
                grant_user=None,
            )

        return authorization.create_authorization_response(
            request=request,
            grant_user=user,
            grant=grant,
        )
    finally:
        remove_sync_session()


def _create_token_response_sync(request: Request):
    try:
        return authorization.create_token_response(request=request)
    finally:
        remove_sync_session()


def _create_endpoint_response_sync(endpoint_name: str, request: Request):
    try:
        return authorization.create_endpoint_response(
            endpoint_name, request=request
        )
    finally:
        remove_sync_session()


def _userinfo_sync(request: Request):
    try:
        with require_oauth.acquire(request, "profile") as token:
            return generate_user_info(token.user, token.scope)
    finally:
        remove_sync_session()


@router.post("/authorize")
async def authorize(  # noqa: PLR0911
    session: Session,
    request: Request,
    decision: Annotated[Literal["approve", "deny"], Form()],
    csrf_token: Annotated[str, Form()],
):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "login_required"}, status_code=401)

    csrf_expected = request.session.get("csrf_token")
    if (
        not csrf_expected
        or not csrf_token
        or not hmac.compare_digest(csrf_expected, csrf_token)
    ):
        return JSONResponse({"error": "invalid_csrf"}, status_code=403)

    request.session.pop("csrf_token", None)

    try:
        uid = UUID(user_id)
    except (ValueError, TypeError):
        return JSONResponse({"error": "invalid_session"}, status_code=401)

    user = await session.scalar(select(User).where(User.id == uid))
    if not user:
        return JSONResponse({"error": "invalid_session"}, status_code=401)

    try:
        return await run_in_threadpool(
            _create_authorization_response_sync,
            request,
            user,
            decision,
        )
    except (OAuth2Error, UnsupportedResponseTypeError) as error:
        return JSONResponse(
            dict(error.get_body()), status_code=error.status_code
        )


@router.post("/token")
async def token(request: Request):
    # Ensure request._body is available for the synchronous payload adapter.
    await request.body()

    # Pass the Starlette request to Authlib; it calls the sync adapter.
    return await run_in_threadpool(_create_token_response_sync, request)


@router.post("/introspect")
async def introspect_token(
    request: Request,
):
    await request.body()
    return await run_in_threadpool(
        _create_endpoint_response_sync, "introspection", request
    )


@router.post("/revoke")
async def revoke_token(
    request: Request,
):

    await request.body()
    return await run_in_threadpool(
        _create_endpoint_response_sync, "revocation", request
    )


@router.get("/userinfo")
def userinfo(request: Request):
    """Request user profile information"""
    return _userinfo_sync(request)


def well_known():

    return {
        "issuer": ENV.OAUTH2_JWT_ISS,
        "authorization_endpoint": f"{ENV.OAUTH2_JWT_ISS}/authorize",
        "token_endpoint": f"{ENV.OAUTH2_JWT_ISS}/oauth/token",
        "userinfo_endpoint": f"{ENV.OAUTH2_JWT_ISS}/oauth/userinfo",
        "jwks_uri": f"{ENV.OAUTH2_JWT_ISS}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": list(scopes.keys()),
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "profile",
            "email",
        ],
        "code_challenge_methods_supported": ["S256"],
    }


def jwks():
    # Return only the public key material.
    public_key = KEY.as_dict(add_kid=True)
    public_key.pop("d", None)
    public_key.pop("p", None)
    public_key.pop("q", None)
    public_key.pop("dp", None)
    public_key.pop("dq", None)
    public_key.pop("qi", None)

    return {"keys": [public_key]}


@well_known_router.get("/.well-known/openid-configuration")
def well_known_root():
    return well_known()


@well_known_router.get("/.well-known/jwks.json")
def jwks_root():
    return jwks()
