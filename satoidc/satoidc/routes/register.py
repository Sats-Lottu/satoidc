import uuid
from pathlib import Path
from typing import Annotated, Optional

import segno
from fastapi import Depends
from fastapi.responses import RedirectResponse
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from satoidc.auth.lnurl import (
    lnurl_auth_events,
    lnurl_auth_temp_storage,
    url_encode,
)
from satoidc.auth.security import hash_password
from satoidc.models import LnurlAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.settings import ENV
from satoidc.utils import safe_redirect
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
    validate_registration_form,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TERMS_FILE = PROJECT_ROOT / "docs" / "legal" / "terms.md"
TERMS_MD = TERMS_FILE.read_text(encoding="utf-8")

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


class LNURLAuthQRRegister:
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
                "Scan with your Lightning Wallet to register without password"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


@router.page("/register")
async def register_page(
    request: Request, session: Session, redirect_to: Optional[str] = "/profile"
):
    redirect_to = safe_redirect(redirect_to)
    if request.session.get("user_id"):
        return RedirectResponse(redirect_to, status_code=303)
    ui.add_head_html(
        '<link href="https://unpkg.com/eva-icons@1.1.3/style/eva-icons.css"'
        ' rel="stylesheet" />'
    )
    register_nonce = uuid.uuid4().hex
    request.session["login_nonce"] = register_nonce
    lnurl_auth_register = LNURLAuthQRRegister(
        base_url=str(request.base_url), session=session
    )
    ui.timer(ENV.LNURL_K1_TTL_SECONDS, lnurl_auth_register.refresh_qrcode)

    @lnurl_auth_events.subscribe
    async def _event_handler(data: dict):
        if data.get("k1") == lnurl_auth_register.k1:
            lnurl_auth_temp_storage[str(register_nonce)] = data.get("user_id")
            ui.navigate.to(f"/auth/lnurl/redirect?redirect_to={redirect_to}")

    with (
        ui.dialog() as dialog,
        ui.card().classes("w-full max-w-lg mx-auto items-center"),
    ):
        lnurl_auth_register.qrcode()
        ui.button("Close", on_click=dialog.close)
    with (
        ui.header(elevated=True)
        .style("background-color:#3874c8; color:white")
        .classes("items-center justify-between px-4")
    ):
        with (
            ui.row()
            .classes("items-center gap-2")
            .on("click", lambda: ui.navigate.to("/"))
        ):
            ui.icon("verified_user")
            ui.label("SatOIDC").classes("text-lg font-bold")

    with ui.card().classes("w-full max-w-lg mx-auto items-center"):
        ui.label("Create account").classes("text-2xl font-bold mb-2")
        ui.label("Fill in the details below.").classes("text-gray-500 mb-6")
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
            session.add(user)
            await session.commit()
            await session.refresh(user)
            request.session["user_id"] = str(user.id)
            ui.notify("Account created!", type="positive")
            ui.navigate.to(redirect_to or "/")

        with (
            ui.dialog(value=True) as dialog_terms,
            ui.card().classes("w-full mx-auto items-center"),
        ):
            ui.markdown(TERMS_MD)
            
        with ui.row().classes("gap-1 items-center"):
            checkbox_terms = ui.checkbox("I accept the ")
            ui.link("terms of service.").on("click", dialog_terms.open)

        # Buttons
        with ui.row().classes("gap-3 mt-4"):
            ui.button("Create account", on_click=submit).classes(
                "w-full"
            ).bind_enabled_from(checkbox_terms, "value")
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props("fab")
