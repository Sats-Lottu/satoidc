import asyncio
import json
import socket
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from http import HTTPStatus

import httpx
import nicegui.run
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.core.container import DockerContainer
from testcontainers.core.exceptions import ContainerStartException
from testcontainers.postgres import PostgresContainer

import satoidc.auth.oauth2 as oauth2_module
import satoidc.models.database as database_module
import satoidc.settings as settings_module
from satoidc.main import app
from satoidc.models.database import get_session
from satoidc.settings import Settings

MAILPIT_IMAGE = "axllent/mailpit:v1.27"
OPENBAO_IMAGE = "openbao/openbao:2.5.2"
OPENBAO_TOKEN = "test-root-token"
MOUNT_EXISTS_STATUS = 400
SERVICE_START_TIMEOUT_SECONDS = 30


def _use_windows_selector_event_loop_policy() -> None:
    if sys.platform == "win32" and hasattr(
        asyncio,
        "WindowsSelectorEventLoopPolicy",
    ):
        asyncio.set_event_loop_policy(
            asyncio.WindowsSelectorEventLoopPolicy()
        )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _get_json(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(url)
    response.raise_for_status()
    return response.json()


async def _wait_for_json_endpoint(url: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            await _get_json(url)
            return
        except (httpx.HTTPError, json.JSONDecodeError):
            await asyncio.sleep(0.2)
    pytest.fail(f"Timed out waiting for {url}")


async def _openbao_request(
    method: str,
    url: str,
    payload: dict | None = None,
) -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.request(
            method,
            url,
            json=payload,
            headers={"X-Vault-Token": OPENBAO_TOKEN},
        )
    response.raise_for_status()
    if not response.content:
        return {}
    return response.json()


async def _wait_for_openbao(addr: str) -> None:
    deadline = time.monotonic() + SERVICE_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            await _openbao_request("GET", f"{addr}/v1/sys/health")
            return
        except (httpx.HTTPError, json.JSONDecodeError, TimeoutError):
            await asyncio.sleep(0.2)
    pytest.fail("Timed out waiting for OpenBao test server")


@pytest.fixture(scope="session")
def postgres_urls() -> Iterator[tuple[str, str]]:
    _use_windows_selector_event_loop_policy()

    try:
        container = PostgresContainer("postgres:16", driver="psycopg")
    except DockerException as exc:
        pytest.skip(f"Docker is not available for Testcontainers: {exc}")

    try:
        with container as postgres:
            database_url = postgres.get_connection_url(driver="psycopg")
            yield database_url, database_url
    except (ContainerStartException, DockerException) as exc:
        pytest.skip(f"PostgreSQL Testcontainer could not start: {exc}")


@pytest.fixture
def migrated_postgres_urls(
    monkeypatch: pytest.MonkeyPatch,
    postgres_urls: tuple[str, str],
) -> tuple[str, str]:
    async_url, sync_url = postgres_urls
    monkeypatch.setattr(
        settings_module,
        "ENV",
        Settings(DATABASE_URL=async_url, SYNC_DATABASE_URL=sync_url),
    )

    alembic_config = Config("alembic.ini")
    command.upgrade(alembic_config, "head")
    return async_url, sync_url


@pytest.fixture
def configured_postgres_database(
    monkeypatch: pytest.MonkeyPatch,
    migrated_postgres_urls: tuple[str, str],
) -> Iterator[tuple[str, str]]:
    async_url, sync_url = migrated_postgres_urls
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

    try:
        yield async_url, sync_url
    finally:
        app.dependency_overrides.clear()
        database_module.SyncSession.remove()
        sync_engine.dispose()
        asyncio.run(async_engine.dispose())


@pytest.fixture
def live_postgres_app(
    monkeypatch: pytest.MonkeyPatch,
    configured_postgres_database: tuple[str, str],
) -> Iterator[str]:
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


@pytest.fixture
async def mailpit() -> AsyncIterator[tuple[str, int, str]]:
    try:
        container = DockerContainer(MAILPIT_IMAGE).with_exposed_ports(
            1025, 8025
        )
        container.start()
    except (ContainerStartException, DockerException) as exc:
        pytest.skip(f"Docker email server unavailable: {exc}")
    try:
        host = container.get_container_host_ip()
        smtp_port = int(container.get_exposed_port(1025))
        http_port = int(container.get_exposed_port(8025))
        api_base = f"http://{host}:{http_port}"
        await _wait_for_json_endpoint(
            f"{api_base}/api/v1/messages",
            SERVICE_START_TIMEOUT_SECONDS,
        )
        yield host, smtp_port, api_base
    finally:
        container.stop()


@pytest.fixture
async def openbao_addr() -> AsyncIterator[str]:
    try:
        container = (
            DockerContainer(OPENBAO_IMAGE)
            .with_exposed_ports(8200)
            .with_env("BAO_DEV_ROOT_TOKEN_ID", OPENBAO_TOKEN)
            .with_command(
                "server -dev -dev-listen-address=0.0.0.0:8200 "
                f"-dev-root-token-id={OPENBAO_TOKEN}"
            )
        )
    except DockerException as exc:
        pytest.skip(f"Docker is not available for Testcontainers: {exc}")

    try:
        with container as openbao:
            addr = (
                f"http://{openbao.get_container_host_ip()}:"
                f"{openbao.get_exposed_port(8200)}"
            )
            await _wait_for_openbao(addr)
            try:
                await _openbao_request(
                    "POST",
                    f"{addr}/v1/sys/mounts/transit",
                    {"type": "transit"},
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != MOUNT_EXISTS_STATUS:
                    raise
            yield addr
    except (ContainerStartException, DockerException) as exc:
        pytest.skip(f"OpenBao Testcontainer could not start: {exc}")
