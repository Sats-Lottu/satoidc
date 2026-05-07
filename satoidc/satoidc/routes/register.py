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
from satoidc.routes.ui_components import (
    DIALOG_CLASSES,
    INPUT_CLASSES,
    LINK_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    auth_context_panel,
    auth_shell,
    card,
)
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
        ui.label("Register with LN Wallet").classes("text-lg font-bold")
        with ui.link(target=f"lightning:{lnurl_auth}").tooltip(
            "Open in Lightning Wallet"
        ):
            ui.image(qrcode.svg_data_uri(light="white", border=1)).classes(
                "w-64 h-64"
            ).tooltip(
                "Scan with your Lightning Wallet to register without password"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center "
            "text-slate-600 dark:text-slate-400"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


@router.page("/register")
async def register_page(  # noqa: PLR0915
    request: Request, session: Session, redirect_to: Optional[str] = "/profile"
):
    redirect_to = safe_redirect(redirect_to)
    if request.session.get("user_id"):
        return RedirectResponse(redirect_to, status_code=303)

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
        card(f"{DIALOG_CLASSES} max-w-lg mx-auto items-center gap-4"),
    ):
        lnurl_auth_register.qrcode()
        ui.button("Close", icon="close", on_click=dialog.close).props(
            "outline"
        ).classes(SECONDARY_BUTTON_CLASSES)

    with auth_shell():
        with ui.grid(columns=2).classes(
            "w-full gap-6 items-start max-md:grid-cols-1"
        ):
            auth_context_panel(
                eyebrow="SatOIDC Onboarding",
                title="Create an identity for OIDC and Lightning access.",
                body=(
                    "Register once, then use SatOIDC as a developer-friendly "
                    "identity provider with password and LNURL-auth access "
                    "paths."
                ),
                features=[
                    (
                        "badge",
                        "Developer-ready account",
                        "Profile, email, and permission state are managed in "
                        "one console.",
                    ),
                    (
                        "bolt",
                        "Lightning compatible",
                        "Wallet registration remains available through the QR "
                        "action.",
                    ),
                    (
                        "rule",
                        "Validated inputs",
                        "Login, email, nickname, and password rules are "
                        "checked before persistence.",
                    ),
                ],
            )
            with card("max-w-xl w-full mx-auto items-stretch gap-4"):
                with ui.column().classes("gap-1"):
                    ui.label("Create account").classes("text-2xl font-bold")
                    ui.label("Fill in the details below.").classes(MUTED_TEXT)
                login_field = (
                    ui.input(
                        "Login",
                        validation={"Invalid login!": is_valid_login},
                    )
                    .classes(INPUT_CLASSES)
                    .tooltip("Lowercase letters and numbers, 6-30 characters")
                )
                email_field = (
                    ui.input(
                        "Email",
                        validation={"Invalid email!": is_valid_email},
                    )
                    .props("type=email")
                    .classes(INPUT_CLASSES)
                ).tooltip("Enter a valid email address")
                nickname_field = (
                    ui.input("Nickname (optional)", value="Satoshi")
                    .classes(INPUT_CLASSES)
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
                    .classes(INPUT_CLASSES)
                    .tooltip(
                        "Password requirements:\n"
                        "- 8-128 characters\n"
                        "- At least one uppercase letter (A-Z)\n"
                        "- At least one lowercase letter (a-z)\n"
                        "- At least one number (0-9)\n"
                        "- At least one special character (!@#$...)"
                    )
                )
                ui.input(
                    "Confirm password",
                    password=True,
                    password_toggle_button=True,
                    validation={
                        "Not same password!": lambda value: (
                            password_field.value == value
                        )
                    },
                ).classes(INPUT_CLASSES)

                async def submit():
                    validation_errors = validate_registration_form(
                        login_field.value,
                        nickname_field.value,
                        password_field.value,
                        email_field.value,
                    ).values()
                    if validation_errors:
                        ui.notify(
                            "\n".join(validation_errors), type="negative"
                        )
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
                    card(f"{DIALOG_CLASSES} mx-auto gap-4"),
                ):
                    ui.label("Terms of service").classes(
                        "text-2xl font-semibold"
                    )
                    ui.separator().classes(
                        "bg-slate-200 dark:bg-slate-800"
                    )
                    ui.markdown(TERMS_MD).classes(
                        "prose prose-slate dark:prose-invert max-w-none "
                        "text-sm leading-7"
                    )

                with ui.row().classes("gap-1 items-center flex-wrap"):
                    checkbox_terms = ui.checkbox("I accept the ")
                    ui.link("terms of service.").on(
                        "click", dialog_terms.open
                    ).classes(LINK_CLASSES)

                with ui.row().classes("gap-3 mt-4 w-full"):
                    ui.button(
                        "Create account", icon="person_add", on_click=submit
                    ).classes(
                        f"w-full {PRIMARY_BUTTON_CLASSES}"
                    ).bind_enabled_from(
                        checkbox_terms, "value"
                    )
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props(
            'fab aria-label="Open LNURL registration QR code"'
        ).classes(PRIMARY_BUTTON_CLASSES)
