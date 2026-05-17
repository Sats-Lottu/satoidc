import time
from secrets import token_urlsafe
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.client_management import (
    CLIENT_DISABLED_AT,
    CLIENT_SECRET_ROTATED_AT,
    CLIENT_UPDATED_AT,
    ClientMetadataValidationError,
    is_client_disabled,
    rotate_client_secret,
    set_client_disabled,
)
from satoidc.enums import (
    GrantTypeEnum,
    ResponseTypeEnum,
    TokenEndpointAuthMethodEnum,
)
from satoidc.models import OAuth2Client

SUPPORTED_GRANT_TYPES = {
    GrantTypeEnum.AUTHORIZATION_CODE.value,
    GrantTypeEnum.REFRESH_TOKEN.value,
}
SUPPORTED_RESPONSE_TYPES = {ResponseTypeEnum.CODE.value}
SUPPORTED_SCOPES = {"openid", "profile", "email"}
SUPPORTED_AUTH_METHODS = {
    method.value for method in TokenEndpointAuthMethodEnum
}


def parse_multiline_values(value: str | None) -> list[str]:
    return [
        line.strip()
        for line in (value or "").splitlines()
        if line.strip()
    ]


def _is_absolute_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _parse_scope(value: str | None) -> str:
    requested_scopes = [scope.strip() for scope in (value or "").split()]
    return " ".join(dict.fromkeys(requested_scopes))


def build_client_metadata(  # noqa: PLR0912, PLR0913
    *,
    client_name: str | None,
    client_uri: str | None,
    scope: str | None,
    redirect_uri: str | None,
    grant_type: str | None,
    response_type: str | None,
    token_endpoint_auth_method: str | None,
) -> dict:
    errors: list[str] = []
    name = (client_name or "").strip()
    uri = (client_uri or "").strip()
    scopes = _parse_scope(scope)
    redirect_uris = parse_multiline_values(redirect_uri)
    grant_types = parse_multiline_values(grant_type)
    response_types = parse_multiline_values(response_type)
    auth_method = (
        token_endpoint_auth_method
        or TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value
    )

    if not name:
        errors.append("Client name is required.")
    if uri and not _is_absolute_http_url(uri):
        errors.append("Client URI must be an absolute HTTP(S) URL.")
    if not redirect_uris:
        errors.append("At least one redirect URI is required.")
    for redirect in redirect_uris:
        if not _is_absolute_http_url(redirect):
            errors.append(
                f"Redirect URI must be an absolute HTTP(S) URL: {redirect}"
            )

    unsupported_grants = sorted(set(grant_types) - SUPPORTED_GRANT_TYPES)
    unsupported_responses = sorted(
        set(response_types) - SUPPORTED_RESPONSE_TYPES
    )
    unsupported_scopes = sorted(set(scopes.split()) - SUPPORTED_SCOPES)
    if not grant_types:
        errors.append("At least one grant type is required.")
    if unsupported_grants:
        errors.append(
            "Unsupported grant types: " + ", ".join(unsupported_grants)
        )
    if not response_types:
        errors.append("At least one response type is required.")
    if unsupported_responses:
        errors.append(
            "Unsupported response types: " + ", ".join(unsupported_responses)
        )
    if ResponseTypeEnum.CODE.value in response_types and (
        GrantTypeEnum.AUTHORIZATION_CODE.value not in grant_types
    ):
        errors.append(
            "The code response type requires the authorization_code grant."
        )
    if not scopes:
        errors.append("At least one scope is required.")
    if unsupported_scopes:
        errors.append("Unsupported scopes: " + ", ".join(unsupported_scopes))
    if auth_method not in SUPPORTED_AUTH_METHODS:
        errors.append(f"Unsupported token endpoint auth method: {auth_method}")

    if errors:
        raise ClientMetadataValidationError(errors)

    return {
        "client_name": name,
        "client_uri": uri,
        "grant_types": grant_types,
        "redirect_uris": redirect_uris,
        "response_types": response_types,
        "scope": scopes,
        "token_endpoint_auth_method": auth_method,
    }


def update_client_metadata(  # noqa: PLR0913
    client: OAuth2Client,
    *,
    client_name: str | None,
    client_uri: str | None,
    scope: str | None,
    redirect_uri: str | None,
    grant_type: str | None,
    response_type: str | None,
    token_endpoint_auth_method: str | None,
    now: int | None = None,
) -> dict:
    current_metadata = client.client_metadata or {}
    next_metadata = build_client_metadata(
        client_name=client_name,
        client_uri=client_uri,
        scope=scope,
        redirect_uri=redirect_uri,
        grant_type=grant_type,
        response_type=response_type,
        token_endpoint_auth_method=token_endpoint_auth_method,
    )
    for key in (CLIENT_DISABLED_AT, CLIENT_SECRET_ROTATED_AT):
        if current_metadata.get(key):
            next_metadata[key] = current_metadata[key]
    next_metadata[CLIENT_UPDATED_AT] = now or int(time.time())
    client.set_client_metadata(next_metadata)
    return next_metadata


async def create_oauth_client(  # noqa: PLR0913
    session: AsyncSession,
    *,
    user_id: UUID,
    client_name: str | None,
    client_uri: str | None,
    scope: str | None,
    redirect_uri: str | None,
    grant_type: str | None,
    response_type: str | None,
    token_endpoint_auth_method: str | None,
) -> tuple[OAuth2Client, str]:
    client_metadata = build_client_metadata(
        client_name=client_name,
        client_uri=client_uri,
        scope=scope,
        redirect_uri=redirect_uri,
        grant_type=grant_type,
        response_type=response_type,
        token_endpoint_auth_method=token_endpoint_auth_method,
    )
    client_id = token_urlsafe(32)
    auth_method = client_metadata["token_endpoint_auth_method"]
    secret = (
        token_urlsafe(64)
        if auth_method != TokenEndpointAuthMethodEnum.NONE.value
        else ""
    )
    client = OAuth2Client(
        user_id=user_id,
        client_id=client_id,
        client_id_issued_at=int(time.time()),
        client_secret=secret,
    )
    client.set_client_metadata(client_metadata)
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client, secret


async def update_oauth_client(  # noqa: PLR0913
    session: AsyncSession,
    client: OAuth2Client,
    *,
    client_name: str | None,
    client_uri: str | None,
    scope: str | None,
    redirect_uri: str | None,
    grant_type: str | None,
    response_type: str | None,
    token_endpoint_auth_method: str | None,
) -> str | None:
    generated_secret = None
    next_metadata = update_client_metadata(
        client,
        client_name=client_name,
        client_uri=client_uri,
        scope=scope,
        redirect_uri=redirect_uri,
        grant_type=grant_type,
        response_type=response_type,
        token_endpoint_auth_method=token_endpoint_auth_method,
    )
    if next_metadata["token_endpoint_auth_method"] == (
        TokenEndpointAuthMethodEnum.NONE.value
    ):
        client.client_secret = ""
    elif not client.client_secret:
        generated_secret = rotate_client_secret(client)
    session.add(client)
    await session.commit()
    return generated_secret


async def rotate_oauth_client_secret(
    session: AsyncSession, client: OAuth2Client
) -> str:
    secret = rotate_client_secret(client)
    session.add(client)
    await session.commit()
    return secret


async def toggle_oauth_client_status(
    session: AsyncSession, client: OAuth2Client
) -> OAuth2Client:
    set_client_disabled(client, disabled=not is_client_disabled(client))
    session.add(client)
    await session.commit()
    return client


async def delete_oauth_client(
    session: AsyncSession, client: OAuth2Client
) -> None:
    await session.delete(client)
    await session.commit()
