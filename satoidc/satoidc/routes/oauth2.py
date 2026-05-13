import hmac
from typing import Annotated, Literal
from uuid import UUID

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from satoidc.auth.oauth2 import (
    authorization,
    generate_user_info,
    require_oauth,
)
from satoidc.auth.oidc_keys import (
    activate_signing_key,
    create_signing_key,
    get_jwks,
    list_signing_keys,
    retire_expired_signing_keys,
    rotate_signing_key,
)
from satoidc.auth.scopes import scopes
from satoidc.auth.security import get_active_user_permissions, is_authorized
from satoidc.enums import PermissionsEnum
from satoidc.models import User
from satoidc.models.database import get_session, remove_sync_session
from satoidc.settings import ENV

router = APIRouter(prefix="/oauth", tags=["OAuth2"])
well_known_router = APIRouter(tags=["OAuth2"])
admin_oidc_keys_router = APIRouter(
    prefix="/admin/oidc/keys", tags=["OIDC Keys"]
)
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
    return get_jwks()


async def _require_key_admin(request: Request) -> str:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="login_required")
    try:
        uid = UUID(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="invalid_session"
        ) from exc
    permissions = await get_active_user_permissions(uid)
    if not is_authorized(
        permissions,
        {PermissionsEnum.ADMIN, PermissionsEnum.ROOT},
        mode="any",
    ):
        raise HTTPException(status_code=403, detail="forbidden")
    return str(uid)


def _key_response(key):
    return {
        "kid": key.kid,
        "alg": key.alg,
        "kty": key.kty,
        "use": key.use,
        "status": key.status,
        "backend_reference": key.backend_reference,
        "created_at": key.created_at.isoformat(),
        "activated_at": (
            key.activated_at.isoformat() if key.activated_at else None
        ),
        "validating_since": (
            key.validating_since.isoformat()
            if key.validating_since
            else None
        ),
        "retired_at": key.retired_at.isoformat()
        if key.retired_at
        else None,
        "retired_after": key.retired_after.isoformat()
        if key.retired_after
        else None,
    }


@well_known_router.get("/.well-known/openid-configuration")
def well_known_root():
    return well_known()


@well_known_router.get("/.well-known/jwks.json")
def jwks_root():
    return JSONResponse(
        jwks(),
        headers={
            "Cache-Control": (
                f"public, max-age={ENV.OIDC_JWKS_CACHE_TTL_SECONDS}"
            )
        },
    )


@admin_oidc_keys_router.get("")
async def admin_list_oidc_keys(request: Request):
    await _require_key_admin(request)
    keys = await run_in_threadpool(list_signing_keys)
    return {"keys": [_key_response(key) for key in keys]}


@admin_oidc_keys_router.post("")
async def admin_create_oidc_key(request: Request):
    actor = await _require_key_admin(request)
    key = await run_in_threadpool(create_signing_key, actor=actor)
    return _key_response(key)


@admin_oidc_keys_router.post("/rotate")
async def admin_rotate_oidc_key(request: Request):
    actor = await _require_key_admin(request)
    key = await run_in_threadpool(rotate_signing_key, actor=actor)
    return _key_response(key)


@admin_oidc_keys_router.post("/retire-expired")
async def admin_retire_expired_oidc_keys(request: Request):
    actor = await _require_key_admin(request)
    retired_count = await run_in_threadpool(
        retire_expired_signing_keys, actor=actor
    )
    return {"retired": retired_count}


@admin_oidc_keys_router.post("/{kid}/activate")
async def admin_activate_oidc_key(kid: str, request: Request):
    actor = await _require_key_admin(request)
    try:
        key = await run_in_threadpool(
            activate_signing_key, kid, actor=actor
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _key_response(key)
