import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest
from docker.errors import DockerException
from testcontainers.core.container import DockerContainer
from testcontainers.core.exceptions import ContainerStartException

import satoidc.services.email_delivery as email_delivery_module
from satoidc.services.email_delivery import (
    send_email_verification,
    send_password_reset,
)

pytestmark = [pytest.mark.integration, pytest.mark.container]

MAILPIT_IMAGE = "axllent/mailpit:v1.27"


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
        return json.loads(response.read())


def _wait_for_mailpit(api_base: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            _get_json(f"{api_base}/api/v1/messages")
            return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.2)
    pytest.fail("Timed out waiting for Mailpit test server")


@pytest.fixture
def mailpit() -> Iterator[tuple[str, int, str]]:
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
        _wait_for_mailpit(api_base)
        yield host, smtp_port, api_base
    finally:
        container.stop()


async def test_smtp_sender_delivers_verification_and_recovery(
    mailpit, make_user, monkeypatch
):
    host, smtp_port, api_base = mailpit
    user = await make_user(email="satoshi@example.com")
    monkeypatch.setattr(email_delivery_module.ENV, "EMAIL_SENDER_MODE", "smtp")
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_HOST", host)
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_PORT", smtp_port)
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_USE_TLS", False)
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_START_TLS", False)
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "SMTP_FROM_EMAIL",
        "no-reply@satoidc.test",
    )

    await send_email_verification(
        user,
        "satoshi@example.com",
        "https://id.example/verify-email?token=verify-token",
    )
    await send_password_reset(
        user,
        "satoshi@example.com",
        "https://id.example/reset-password?token=reset-token",
    )

    messages = _get_json(f"{api_base}/api/v1/messages")["messages"]
    subjects = {message["Subject"] for message in messages}
    recipients = {
        address["Address"]
        for message in messages
        for address in message["To"]
    }
    assert "Verify your SatOIDC email" in subjects
    assert "Reset your SatOIDC password" in subjects
    assert recipients == {"satoshi@example.com"}
