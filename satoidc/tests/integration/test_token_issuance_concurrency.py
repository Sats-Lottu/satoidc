import asyncio
import base64
import hashlib
import socket
import threading
import time
from collections.abc import Iterator
from http import HTTPStatus

import httpx
import nicegui.run
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

import satoidc.auth.oauth2 as oauth2_module
import satoidc.models.database as database_module
import satoidc.settings as settings_module
from satoidc.main import app
from satoidc.models import OAuth2AuthorizationCode, OAuth2Client, User
from satoidc.models.database import get_session
from satoidc.settings import Settings

pytestmark = [pytest.mark.integration, pytest.mark.container, pytest.mark.load]

CONCURRENT_TOKEN_EXCHANGES = 8
TOKEN_SMOKE_TIMEOUT_SECONDS = 20


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.fixture
def postgres_app(
    monkeypatch: pytest.MonkeyPatch,
    postgres_urls: tuple[str, str],
) -> Iterator[str]:
    async_url, sync_url = postgres_urls

    env = Settings(DATABASE_URL=async_url, SYNC_DATABASE_URL=sync_url)
    monkeypatch.setattr(settings_module, "ENV", env)

    alembic_config = Config("alembic.ini")
    command.upgrade(alembic_config, "head")

    async_engine = create_async_engine(async_url)
    sync_engine = create_engine(sync_url)
    testing_session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=sync_engine,
    )

    database_module.SyncSession.remove()
    database_module.SyncSession.configure(bind=sync_engine)
    monkeypatch.setattr(database_module, "engine", async_engine)
    monkeypatch.setattr(database_module, "sync_engine", sync_engine)
    monkeypatch.setattr(database_module, "SessionLocal", testing_session_local)
    monkeypatch.setattr(database_module, "db", database_module.SyncSession)
    monkeypatch.setattr(oauth2_module, "db", database_module.SyncSession)

    async def override_get_session():
        async with AsyncSession(
            async_engine,
            expire_on_commit=False,
        ) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(nicegui.run, "setup", lambda: None)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            lifespan="on",
            ws="none",
        )
    )

    def run_server() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"{base_url}/.well-known/openid-configuration",
                timeout=1,
            )
            if response.status_code == HTTPStatus.OK:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("Timed out waiting for SatOIDC integration server")

    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        app.dependency_overrides.clear()
        database_module.SyncSession.remove()
        sync_engine.dispose()
        asyncio.run(async_engine.dispose())


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


def test_token_issuance_concurrency_smoke(postgres_app: str) -> None:
    client_id, verifier, codes = _seed_token_exchange_data()

    async def run_smoke() -> list[httpx.Response]:
        async with httpx.AsyncClient(
            base_url=postgres_app,
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
