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
from satoidc.settings import ENV

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------
# Helpers
# ---------------------------


def encode_query_value(value: str) -> str:
    """URL-encode seguro para valores em querystring."""
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
    # (A) anti-post-direto / anti-replay do login flow
    expected_nonce = request.session.get("login_nonce")
    if (
        not expected_nonce
        or not login_form.login_nonce
        or login_form.login_nonce != expected_nonce
    ):
        request.session.pop("login_nonce", None)
        return RedirectResponse(url="/login?err=bad_flow", status_code=303)

    request.session.pop("login_nonce", None)

    # (B) redirect_to seguro e URL-encoded para querystring em caso de erro
    nxt = login_form.redirect_to

    # (C) autentica
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

    # (D) grava sessão e redireciona (redirect_to pode conter query)
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
        ui.label("Login with LN Wallet")
        with ui.link(target=f"lightning:{lnurl_auth}").tooltip(
            "Open in Lightning Wallet"
        ):
            ui.image(qrcode.svg_data_uri(light="white", border=1)).classes(
                "w-64"
            ).tooltip(
                "Scan with your Lightning Wallet to login to your"
                " account without password"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


@router.page("/login")
async def login_page(
    session: Session,
    request: Request,
    redirect_to: Optional[str] = "/",
    err: Optional[str] = None,
):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)
    # gera nonce do login (não confundir com OIDC nonce)
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

    # QR Code Dialog
    with (
        ui.dialog() as dialog,
        ui.card().classes("w-full max-w-lg mx-auto items-center"),
    ):
        lnurl_auth_login.qrcode()
        ui.button("Close", on_click=dialog.close)

    # Header
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
        ui.label("Sign in").classes("text-2xl font-bold")
        ui.label("Use your account to continue.").classes("text-gray-500")
        match err:
            case None:
                pass
            case "invalid":
                ui.label("Invalid credentials.").classes("text-red-500 mb-2")
            case "bad_flow":
                ui.label("Invalid login flow. Please try again.").classes(
                    "text-red-500 mb-2"
                )
            case _:
                ui.label("Unknown error!").classes("text-red-500 mb-2")

        with (
            ui.element("form")
            .props('method="post" action="/login"')
            .classes("flex flex-col gap-3 w-full")
        ):
            ui.input("Email or Login").props(
                "name='identifier' autocomplete='username'"
            ).classes("w-full")
            ui.input("Password").props(
                "name='password' type='password'"
                " autocomplete='current-password'"
            ).classes("w-full")

            # hidden redirect_to + login_nonce
            ui.element("input").props(
                f"type='hidden' name='redirect_to' value='{redirect_to}'"
            )
            ui.element("input").props(
                f"type='hidden' name='login_nonce' value='{login_nonce}'"
            )

            with ui.row().classes("gap-4 w-full justify-center"):
                ui.button(
                    "Cancel", on_click=lambda: ui.navigate.to("/")
                ).props("outline")
                ui.button("Login").props("type='submit'")

        with ui.row().classes("gap-4 mt-4 justify-center"):
            ui.label("Don't have an account?")
            ui.link("register", "/register")
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props("fab")


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
