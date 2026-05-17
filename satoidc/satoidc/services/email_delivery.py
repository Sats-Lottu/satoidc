import logging
from email.message import EmailMessage

import aiosmtplib

from satoidc.models import User
from satoidc.settings import ENV

log = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """Raised when configured email delivery fails."""


async def _send_message(to_email: str, subject: str, body: str) -> None:
    if ENV.EMAIL_SENDER_MODE == "disabled":
        log.info(
            "Email delivery skipped",
            extra={
                "event_name": "email.delivery_skipped",
                "component": "email_delivery",
                "outcome": "skipped",
                "reason": "disabled",
            },
        )
        return
    if ENV.EMAIL_SENDER_MODE == "console":
        log.info(
            "Email delivery prepared",
            extra={
                "event_name": "email.delivery_console",
                "component": "email_delivery",
                "outcome": "prepared",
                "recipient": to_email,
                "subject": subject,
            },
        )
        return
    if not ENV.SMTP_HOST:
        raise EmailDeliveryError("SMTP_HOST is required for SMTP delivery")

    message = EmailMessage()
    message["From"] = ENV.SMTP_FROM_EMAIL
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    try:
        await aiosmtplib.send(
            message,
            hostname=ENV.SMTP_HOST,
            port=ENV.SMTP_PORT,
            username=ENV.SMTP_USERNAME or None,
            password=ENV.SMTP_PASSWORD or None,
            use_tls=ENV.SMTP_USE_TLS,
            start_tls=ENV.SMTP_START_TLS,
        )
    except Exception as exc:
        raise EmailDeliveryError("SMTP delivery failed") from exc


async def send_email_verification(
    user: User, email: str, verification_url: str
) -> None:
    await _send_message(
        email,
        "Verify your SatOIDC email",
        (
            f"Hello {user.nickname or 'Satoshi'},\n\n"
            "Verify this email address for your SatOIDC account:\n"
            f"{verification_url}\n\n"
            "If you did not request this, ignore this message.\n"
        ),
    )


async def send_password_reset(
    user: User, email: str, reset_url: str
) -> None:
    await _send_message(
        email,
        "Reset your SatOIDC password",
        (
            f"Hello {user.nickname or 'Satoshi'},\n\n"
            "Use this link to set a new SatOIDC password:\n"
            f"{reset_url}\n\n"
            "If you did not request this, ignore this message.\n"
        ),
    )
