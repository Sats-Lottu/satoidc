import asyncio
import json
import time
from collections.abc import AsyncIterator
from types import SimpleNamespace

import httpx
import pytest
from docker.errors import DockerException
from joserfc import jwt
from joserfc.jwk import RSAKey
from testcontainers.core.container import DockerContainer
from testcontainers.core.exceptions import ContainerStartException

import satoidc.auth.oidc_signing_backends as signing_backends_module
from satoidc.auth.oauth2 import OpenIDCode
from satoidc.auth.oidc_keys import create_signing_key

pytestmark = [pytest.mark.integration, pytest.mark.container]

OPENBAO_IMAGE = "openbao/openbao:2.5.2"
OPENBAO_TOKEN = "test-root-token"
MOUNT_EXISTS_STATUS = 400


class Client:
    @staticmethod
    def get_client_id():
        return "client-1"


async def _request(
    method: str,
    url: str,
    token: str,
    payload: dict | None = None,
) -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.request(
            method,
            url,
            json=payload,
            headers={"X-Vault-Token": token},
        )
    response.raise_for_status()
    if not response.content:
        return {}
    return response.json()


async def _wait_for_openbao(addr: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            await _request("GET", f"{addr}/v1/sys/health", OPENBAO_TOKEN)
            return
        except (
            httpx.HTTPError,
            json.JSONDecodeError,
            TimeoutError,
        ):
            await asyncio.sleep(0.2)
    pytest.fail("Timed out waiting for OpenBao test server")


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
                await _request(
                    "POST",
                    f"{addr}/v1/sys/mounts/transit",
                    OPENBAO_TOKEN,
                    {"type": "transit"},
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != MOUNT_EXISTS_STATUS:
                    raise
            yield addr
    except (ContainerStartException, DockerException) as exc:
        pytest.skip(f"OpenBao Testcontainer could not start: {exc}")


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
