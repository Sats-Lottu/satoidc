import pytest

import satoidc.services.email_delivery as email_delivery_module
from satoidc.models import User
from satoidc.services.email_delivery import (
    EmailDeliveryError,
    send_email_verification,
    send_password_reset,
)


def user(nickname: str | None = "Satoshi") -> User:
    return User(
        lnurl_pubkey=None,
        login="satoshi",
        email="satoshi@example.com",
        password_hash=None,
        nickname=nickname,
    )


@pytest.fixture
def email_env(monkeypatch):
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "SMTP_FROM_EMAIL",
        "no-reply@example.com",
    )
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "SMTP_HOST",
        "smtp.example.com",
    )
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_PORT", 2525)
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "SMTP_USERNAME",
        "smtp-user",
    )
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "SMTP_PASSWORD",
        "smtp-secret",
    )
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_USE_TLS", False)
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_START_TLS", True)


async def test_email_delivery_disabled_logs_skip(
    email_env, monkeypatch, caplog
):
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "EMAIL_SENDER_MODE",
        "disabled",
    )

    await send_email_verification(
        user(),
        "satoshi@example.com",
        "https://id.example/verify-email?token=abc",
    )

    assert any(
        record.event_name == "email.delivery_skipped"
        and record.outcome == "skipped"
        for record in caplog.records
    )


async def test_email_delivery_console_logs_prepared(
    email_env, monkeypatch, caplog
):
    monkeypatch.setattr(
        email_delivery_module.ENV,
        "EMAIL_SENDER_MODE",
        "console",
    )

    await send_password_reset(
        user(nickname=None),
        "satoshi@example.com",
        "https://id.example/reset-password?token=abc",
    )

    assert any(
        record.event_name == "email.delivery_console"
        and record.recipient == "satoshi@example.com"
        and record.subject == "Reset your SatOIDC password"
        for record in caplog.records
    )


async def test_email_delivery_smtp_sends_message(email_env, monkeypatch):
    sent = {}

    async def fake_send(message, **kwargs):
        sent["message"] = message
        sent["kwargs"] = kwargs

    monkeypatch.setattr(email_delivery_module.ENV, "EMAIL_SENDER_MODE", "smtp")
    monkeypatch.setattr(email_delivery_module.aiosmtplib, "send", fake_send)

    await send_email_verification(
        user(),
        "satoshi@example.com",
        "https://id.example/verify-email?token=abc",
    )

    assert sent["message"]["From"] == "no-reply@example.com"
    assert sent["message"]["To"] == "satoshi@example.com"
    assert sent["message"]["Subject"] == "Verify your SatOIDC email"
    assert "https://id.example/verify-email?token=abc" in sent[
        "message"
    ].get_content()
    assert sent["kwargs"] == {
        "hostname": "smtp.example.com",
        "port": 2525,
        "username": "smtp-user",
        "password": "smtp-secret",
        "use_tls": False,
        "start_tls": True,
    }


async def test_email_delivery_smtp_requires_host(email_env, monkeypatch):
    monkeypatch.setattr(email_delivery_module.ENV, "EMAIL_SENDER_MODE", "smtp")
    monkeypatch.setattr(email_delivery_module.ENV, "SMTP_HOST", "")

    with pytest.raises(EmailDeliveryError, match="SMTP_HOST"):
        await send_password_reset(
            user(),
            "satoshi@example.com",
            "https://id.example/reset-password?token=abc",
        )


async def test_email_delivery_wraps_smtp_errors(email_env, monkeypatch):
    async def fail_send(*args, **kwargs):
        raise RuntimeError("connection failed")

    monkeypatch.setattr(email_delivery_module.ENV, "EMAIL_SENDER_MODE", "smtp")
    monkeypatch.setattr(email_delivery_module.aiosmtplib, "send", fail_send)

    with pytest.raises(EmailDeliveryError, match="SMTP delivery failed"):
        await send_email_verification(
            user(),
            "satoshi@example.com",
            "https://id.example/verify-email?token=abc",
        )
