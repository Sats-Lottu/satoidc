from typing import Annotated

import segno
from fastapi import Depends, Request
from nicegui import APIRouter, app, ui
from satoidc.auth.lnurl import lnurl_auth_events, url_encode
from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import LnurlAuthChallenge, Permission, User
from satoidc.models.database import get_session
from satoidc.settings import ENV
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
    validate_registration_form,
)
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


def finalizing_setup():
    ui.notify("Root user created!", type="positive")
    ui.notify("Finalizing setup...", type="positive")
    ui.timer(0.8, app.shutdown, once=True)


class LNURLAuthQRRegisterRoot:
    def __init__(self, base_url: str, session: Session):
        self.base_url = base_url
        self.k1 = None
        self.action = "register"
        self.session = session

    async def refresh_qrcode(self):
        challenge = LnurlAuthChallenge(action=self.action)
        self.session.add(challenge)
        await self.session.commit()
        await self.session.refresh(challenge)
        self.k1 = challenge.k1
        self.qrcode.refresh()

    @ui.refreshable_method
    def qrcode(self):
        lnurl_auth = url_encode(
            f"{self.base_url}auth/lnurl/callback?tag=login&k1={self.k1}&action={self.action}"
        )
        qrcode = segno.make_qr(lnurl_auth, error="l")
        ui.label("Login with LN Wallet")
        with ui.link(target=f"lightning:{lnurl_auth}").tooltip(
            "Open in Lightning Wallet"
        ):
            ui.image(qrcode.svg_data_uri(light="white", border=1)).classes(
                "w-64"
            ).tooltip(
                "Scan with your Lightning Wallet to register as root user"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


@router.page("/", dark=True)
async def set_root(session: Session, request: Request):
    ui.add_head_html(
        '<link href="https://unpkg.com/eva-icons@1.1.3/style/eva-icons.css"'
        ' rel="stylesheet" />'
    )

    lnurl_auth_register_root = LNURLAuthQRRegisterRoot(
        base_url=str(request.base_url), session=session
    )
    ui.timer(ENV.LNURL_K1_TTL_SECONDS, lnurl_auth_register_root.refresh_qrcode)

    @lnurl_auth_events.subscribe
    async def _event_handler(data: dict):
        if data.get("k1") == lnurl_auth_register_root.k1:
            permission = Permission(
                permission_type=PermissionsEnum.ROOT,
                granted_by=None,
                reason="Initial root user created via setup wizard",
                expiration_date=None,
                user_id=data.get("user_id"),
            )

            session.add(permission)
            await session.commit()
            finalizing_setup()

    with (
        ui.dialog() as dialog,
        ui.card().classes("w-full max-w-lg mx-auto items-center"),
    ):
        lnurl_auth_register_root.qrcode()
        ui.button("Close", on_click=dialog.close)
    # Refresh QR code every 60 seconds to prevent reuse of old challenges

    # Header
    with (
        ui.header(elevated=True)
        .style("background-color:#3874c8; color:white")
        .classes("items-center justify-between px-4")
    ):
        with ui.row().classes("items-center gap-2"):
            ui.icon("verified_user")
            ui.label("SatOIDC").classes("text-lg font-bold")

        with ui.link(
            target="https://github.com/Sats-Lottu/satoidc", new_tab=True
        ).classes("text-white"):
            ui.icon("eva-github").style("font-size:28px; padding:0")

    # Content
    with ui.column().classes("flex justify-center w-full items-center"):
        ui.label("Create Root").classes("text-2xl font-bold mb-2")

        with ui.card().classes("w-full max-w-lg mx-auto items-center"):
            login_field = (
                ui.input(
                    "Login",
                    validation={"Invalid login!": is_valid_login},
                )
                .classes("w-full")
                .tooltip("Lowercase letters and numbers, 6-30 characters")
            )
            email_field = (
                ui.input(
                    "Email",
                    validation={"Invalid email!": is_valid_email},
                )
                .props("type=email")
                .classes("w-full")
            ).tooltip("Enter a valid email address")
            nickname_field = (
                ui.input("Nickname (optional)", value="Satoshi")
                .classes("w-full")
                .tooltip(
                    "Letters, numbers, dots, underscores or hyphens, "
                    "2-80 characters"
                )
            )

            password_field = (
                ui.input(
                    "Password",
                    password=True,
                    password_toggle_button=True,
                    validation={
                        "Weak password!": lambda v: (
                            is_valid_password(v) if len(v) >= 0 else True
                        ),
                    },
                )
                .classes("w-full")
                .tooltip(
                    "Password requirements:\n"
                    "• 8-128 characters\n"
                    "• At least one uppercase letter (A-Z)\n"
                    "• At least one lowercase letter (a-z)\n"
                    "• At least one number (0-9)\n"
                    "• At least one special character (!@#$...)"
                )
            )
            _confirm = ui.input(
                "Confirm password",
                password=True,
                password_toggle_button=True,
                validation={
                    "Not same password!": lambda value: (
                        password_field.value == value
                    )
                },
            ).classes("w-full")

            async def submit():
                validation_errors = validate_registration_form(
                    login_field.value,
                    nickname_field.value,
                    password_field.value,
                    email_field.value,
                ).values()
                if validation_errors:
                    ui.notify("\n".join(validation_errors), type="negative")
                    return
                login = login_field.value.strip()
                email = email_field.value.strip().lower()
                nickname = (nickname_field.value or "").strip() or None
                pw_hash = hash_password(password_field.value)

                user = User(
                    lnurl_pubkey=None,
                    login=login,
                    email=email,
                    nickname=nickname,
                    password_hash=pw_hash,
                )
                permission = Permission(
                    permission_type=PermissionsEnum.ROOT,
                    granted_by=None,
                    reason="Initial root user created via setup wizard",
                    expiration_date=None,
                    user_id=user.id,
                )
                session.add(user)
                session.add(permission)
                await session.commit()
                await session.refresh(user)
                finalizing_setup()

            # Buttons
            with ui.row().classes("gap-3 mt-4"):
                ui.button("Create account", on_click=submit).classes("w-full")
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props("fab")
