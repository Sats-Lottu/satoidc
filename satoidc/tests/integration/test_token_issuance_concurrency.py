import asyncio
import base64
import hashlib
import time
from http import HTTPStatus

import httpx
import pytest

import satoidc.models.database as database_module
from satoidc.models import OAuth2AuthorizationCode, OAuth2Client, User

pytestmark = [pytest.mark.integration, pytest.mark.container]

CONCURRENT_TOKEN_EXCHANGES = 8
TOKEN_SMOKE_TIMEOUT_SECONDS = 20


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _seed_token_exchange_data() -> tuple[str, str, list[str]]:
    verifier = "token-smoke-verifier-0123456789abcdef0123456789"
    challenge = _pkce_challenge(verifier)
    client_id = "token-smoke-public-client"

    session = database_module.SyncSession()
    try:
        user = User(
            lnurl_pubkey=None,
            email="token-smoke@example.com",
            login="tokensmoke",
            password_hash=None,
            nickname="Token Smoke",
        )
        session.add(user)
        session.flush()

        client = OAuth2Client(
            user_id=user.id,
            client_id=client_id,
            client_id_issued_at=1,
        )
        client.set_client_metadata(
            {
                "client_name": "Token Smoke Client",
                "scope": "openid profile",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }
        )
        session.add(client)

        codes = []
        for index in range(CONCURRENT_TOKEN_EXCHANGES):
            code = f"token-smoke-code-{index}"
            codes.append(code)
            session.add(
                OAuth2AuthorizationCode(
                    code=code,
                    client_id=client_id,
                    redirect_uri="https://client.example/callback",
                    scope="openid profile",
                    user_id=user.id,
                    nonce=f"nonce-{index}",
                    code_challenge=challenge,
                    code_challenge_method="S256",
                    auth_time=int(time.time()),
                )
            )

        session.commit()
        return client_id, verifier, codes
    finally:
        session.close()


async def _exchange_code(
    client: httpx.AsyncClient,
    client_id: str,
    verifier: str,
    code: str,
) -> httpx.Response:
    return await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": "https://client.example/callback",
            "code_verifier": verifier,
        },
    )


def test_token_issuance_concurrency_smoke(live_postgres_app: str) -> None:
    client_id, verifier, codes = _seed_token_exchange_data()

    async def run_smoke() -> list[httpx.Response]:
        async with httpx.AsyncClient(
            base_url=live_postgres_app,
            timeout=TOKEN_SMOKE_TIMEOUT_SECONDS,
        ) as client:
            return await asyncio.gather(
                *[
                    _exchange_code(client, client_id, verifier, code)
                    for code in codes
                ]
            )

    started_at = time.perf_counter()
    responses = asyncio.run(run_smoke())
    elapsed = time.perf_counter() - started_at

    assert elapsed < TOKEN_SMOKE_TIMEOUT_SECONDS
    assert [response.status_code for response in responses] == [
        HTTPStatus.OK
    ] * CONCURRENT_TOKEN_EXCHANGES
    assert all("access_token" in response.json() for response in responses)
