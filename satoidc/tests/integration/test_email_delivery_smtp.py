import httpx
import pytest

import satoidc.services.email_delivery as email_delivery_module
from satoidc.services.email_delivery import (
    send_email_verification,
    send_password_reset,
)

pytestmark = [pytest.mark.integration, pytest.mark.container]


async def _get_json(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(url)
    response.raise_for_status()
    return response.json()


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

    messages = (await _get_json(f"{api_base}/api/v1/messages"))["messages"]
    subjects = {message["Subject"] for message in messages}
    recipients = {
        address["Address"]
        for message in messages
        for address in message["To"]
    }
    assert "Verify your SatOIDC email" in subjects
    assert "Reset your SatOIDC password" in subjects
    assert recipients == {"satoshi@example.com"}
