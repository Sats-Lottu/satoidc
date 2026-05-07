import uuid
from typing import Annotated, Optional
from urllib.parse import quote

import segno
from fastapi import Depends, Form, Request
from fastapi.responses import RedirectResponse
from nicegui import APIRouter, ui
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.lnurl import (
    lnurl_auth_events,
    lnurl_auth_temp_storage,
    url_encode,
)
from satoidc.auth.security import verify_password
from satoidc.models import LnurlAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    DIALOG_CLASSES,
    ERROR_TEXT,
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

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------
# Helpers
# ---------------------------


def encode_query_value(value: str) -> str:
    """Safely URL-encode querystring values."""
    return quote(value or "", safe="")


# ==========================================================
# LOGIN
# ==========================================================


class LoginSchema(BaseModel):
    identifier: str
    password: str
    redirect_to: Optional[str] = None
    login_nonce: Optional[str] = None


LoginForm = Annotated[LoginSchema, Form()]


@router.post("/login")
async def login_post(
    session: Session,
    request: Request,
    login_form: LoginForm,
):
    # (A) Prevent direct posts and replay attempts in the login flow.
    expected_nonce = request.session.get("login_nonce")
    if (
        not expected_nonce
        or not login_form.login_nonce
        or login_form.login_nonce != expected_nonce
    ):
        request.session.pop("login_nonce", None)
        return RedirectResponse(url="/login?err=bad_flow", status_code=303)

    request.session.pop("login_nonce", None)

    # (B) Keep redirect_to URL-encoded when returning validation errors.
    nxt = login_form.redirect_to

    # (C) Authenticate the user.
    user = await session.scalar(
        select(User).where(
            (User.email == login_form.identifier)
            | (User.login == login_form.identifier)
        )
    )
    if not user or not verify_password(
        login_form.password, user.password_hash
    ):
        return RedirectResponse(
            url=f"/login?err=invalid&redirect_to={encode_query_value(nxt)}",
            status_code=303,
        )

    # (D) Store the session and redirect. redirect_to may contain a query.
    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=nxt, status_code=303)


class LNURLAuthQRLogin:
    def __init__(self, base_url: str, session: Session):
        self.base_url = base_url
        self.k1 = None
        self.action = "login"
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
        ui.label("Login with LN Wallet").classes("text-lg font-bold")
        with ui.link(target=f"lightning:{lnurl_auth}").tooltip(
            "Open in Lightning Wallet"
        ):
            ui.image(qrcode.svg_data_uri(light="white", border=1)).classes(
                "w-64 h-64"
            ).tooltip(
                "Scan with your Lightning Wallet to login to your"
                " account without password"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center "
            "text-slate-600 dark:text-slate-400"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


@router.page("/login")
async def login_page(
    session: Session,
    request: Request,
    redirect_to: Optional[str] = "/profile",
    err: Optional[str] = None,
):
    if request.session.get("user_id"):
        return RedirectResponse(redirect_to, status_code=303)
    # Generate a login nonce; do not confuse it with the OIDC nonce.
    login_nonce = uuid.uuid4().hex
    request.session["login_nonce"] = login_nonce

    lnurl_auth_login = LNURLAuthQRLogin(
        base_url=str(request.base_url), session=session
    )
    ui.timer(ENV.LNURL_K1_TTL_SECONDS, lnurl_auth_login.refresh_qrcode)

    @lnurl_auth_events.subscribe
    async def _event_handler(data: dict):
        if data.get("k1") == lnurl_auth_login.k1:
            lnurl_auth_temp_storage[str(login_nonce)] = data.get("user_id")
            ui.navigate.to(f"/auth/lnurl/redirect?redirect_to={redirect_to}")

    with (
        ui.dialog() as dialog,
        card(f"{DIALOG_CLASSES} max-w-lg mx-auto items-center gap-4"),
    ):
        lnurl_auth_login.qrcode()
        ui.button("Close", icon="close", on_click=dialog.close).props(
            "outline"
        ).classes(SECONDARY_BUTTON_CLASSES)

    with auth_shell():
        with ui.grid(columns=2).classes(
            "w-full gap-6 items-stretch max-md:grid-cols-1"
        ):
            auth_context_panel(
                eyebrow="SatOIDC Access",
                title="Credentials or Lightning wallet access.",
                body=(
                    "Use the standard account flow for OAuth/OIDC sessions, "
                    "or open the LNURL-auth QR action when wallet-based "
                    "access is more convenient."
                ),
                features=[
                    (
                        "shield",
                        "Nonce-protected flow",
                        "Each login page render creates a fresh form nonce.",
                    ),
                    (
                        "qr_code",
                        "Wallet fallback",
                        "LNURL-auth remains available as a floating QR "
                        "action.",
                    ),
                    (
                        "route",
                        "Redirect-aware",
                        "The original destination is preserved after login.",
                    ),
                ],
            )
            with card("max-w-lg w-full mx-auto items-stretch gap-4"):
                with ui.column().classes("gap-1"):
                    ui.label("Sign in").classes("text-2xl font-bold")
                    ui.label("Use your account to continue.").classes(
                        MUTED_TEXT
                    )
                match err:
                    case None:
                        pass
                    case "invalid":
                        ui.label("Invalid credentials.").classes(
                            f"{ERROR_TEXT} mb-2"
                        )
                    case "bad_flow":
                        ui.label(
                            "Invalid login flow. Please try again."
                        ).classes(f"{ERROR_TEXT} mb-2")
                    case _:
                        ui.label("Unknown error.").classes(
                            f"{ERROR_TEXT} mb-2"
                        )

                with (
                    ui.element("form")
                    .props('method="post" action="/login"')
                    .classes("flex flex-col gap-3 w-full")
                ):
                    ui.input("Email or Login").props(
                        "name='identifier' autocomplete='username'"
                    ).classes(INPUT_CLASSES)
                    ui.input("Password").props(
                        "name='password' type='password'"
                        " autocomplete='current-password'"
                    ).classes(INPUT_CLASSES)

                    ui.element("input").props(
                        "type='hidden' name='redirect_to' "
                        f"value='{redirect_to}'"
                    )
                    ui.element("input").props(
                        "type='hidden' name='login_nonce' "
                        f"value='{login_nonce}'"
                    )

                    with ui.row().classes(
                        "gap-3 w-full justify-end max-sm:flex-col-reverse"
                    ):
                        ui.button(
                            "Cancel",
                            icon="close",
                            on_click=lambda: ui.navigate.to("/"),
                        ).classes(SECONDARY_BUTTON_CLASSES)
                        ui.button("Login", icon="login").props(
                            "type='submit'"
                        ).classes(PRIMARY_BUTTON_CLASSES)

                with ui.row().classes("gap-2 mt-2 justify-center"):
                    ui.label("Don't have an account?").classes(MUTED_TEXT)
                    ui.link("Register", "/register").classes(LINK_CLASSES)
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props(
            'fab aria-label="Open LNURL login QR code"'
        ).classes(PRIMARY_BUTTON_CLASSES)


@router.page("/auth/lnurl/redirect")
async def lnurl_redirect(request: Request, redirect_to: Optional[str] = "/"):
    expected_nonce = request.session.get("login_nonce")
    user_id = None
    if expected_nonce:
        user_id = lnurl_auth_temp_storage.get(expected_nonce)
    lnurl_auth_temp_storage.pop(expected_nonce, None)
    if user_id:
        request.session["user_id"] = str(user_id)
    ui.label("Redirecting...").classes("text-lg font-bold")
    ui.navigate.to(redirect_to)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
