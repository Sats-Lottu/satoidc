from html import escape
from typing import Annotated

from fastapi import Depends
from fastapi.responses import RedirectResponse
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    ERROR_TEXT,
    INPUT_CLASSES,
    LINK_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    auth_shell,
    card,
)
from satoidc.schemas.recovery import ForgotPasswordForm, ResetPasswordForm
from satoidc.services.email_delivery import EmailDeliveryError
from satoidc.services.email_tokens import (
    RECOVERY_REQUEST_MESSAGE,
    EmailTokenError,
    request_password_reset,
    reset_password_with_token,
    verify_email_token,
)

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/verify-email")
async def verify_email(
    session: Session, token: str | None = None
) -> RedirectResponse:
    try:
        await verify_email_token(session, token)
    except EmailTokenError:
        return RedirectResponse("/login?err=email_verification", 303)
    return RedirectResponse("/profile", 303)


@router.post("/forgot-password")
async def forgot_password_post(
    session: Session,
    request: Request,
    form: ForgotPasswordForm,
):
    try:
        await request_password_reset(
            session,
            form.email,
            request_base_url=str(request.base_url),
            request_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except EmailDeliveryError:
        # Keep enumeration resistance: the public response remains generic.
        pass
    return RedirectResponse("/forgot-password?sent=1", 303)


@router.post("/reset-password")
async def reset_password_post(
    session: Session,
    form: ResetPasswordForm,
):
    try:
        await reset_password_with_token(
            session,
            form.token,
            new_password=form.password,
            confirm_password=form.confirm_password,
        )
    except EmailTokenError:
        return RedirectResponse("/reset-password?err=invalid", 303)
    return RedirectResponse("/login?reset=1", 303)


@router.page("/forgot-password")
async def forgot_password_page(sent: bool = False):  # pragma: no cover
    with auth_shell():
        with card("max-w-lg w-full mx-auto items-stretch gap-4"):
            ui.label("Recover account").classes("text-2xl font-bold")
            ui.label(
                "Enter the email linked to your account."
            ).classes(MUTED_TEXT)
            if sent:
                ui.label(RECOVERY_REQUEST_MESSAGE).classes(MUTED_TEXT)
            with (
                ui.element("form")
                .props('method="post" action="/forgot-password"')
                .classes("flex flex-col gap-3 w-full")
            ):
                ui.input("Email").props(
                    "name='email' type=email autocomplete='email'"
                ).classes(INPUT_CLASSES)
                with ui.row().classes(
                    "gap-3 w-full justify-end max-sm:flex-col-reverse"
                ):
                    ui.button(
                        "Back to login",
                        icon="arrow_back",
                        on_click=lambda: ui.navigate.to("/login"),
                    ).classes(SECONDARY_BUTTON_CLASSES)
                    ui.button("Send recovery link", icon="mail").props(
                        "type='submit'"
                    ).classes(PRIMARY_BUTTON_CLASSES)


@router.page("/reset-password")
async def reset_password_page(
    token: str | None = None, err: str | None = None
):  # pragma: no cover
    safe_token = escape(token or "", quote=True)
    with auth_shell():
        with card("max-w-lg w-full mx-auto items-stretch gap-4"):
            ui.label("Reset password").classes("text-2xl font-bold")
            if err:
                ui.label("Invalid or expired reset link.").classes(ERROR_TEXT)
                ui.link("Request a new link", "/forgot-password").classes(
                    LINK_CLASSES
                )
                return
            ui.label("Choose a new password.").classes(MUTED_TEXT)
            with (
                ui.element("form")
                .props('method="post" action="/reset-password"')
                .classes("flex flex-col gap-3 w-full")
            ):
                ui.element("input").props(
                    "type='hidden' name='token' " f"value='{safe_token}'"
                )
                ui.input("New password").props(
                    "name='password' type='password' "
                    "autocomplete='new-password'"
                ).classes(INPUT_CLASSES)
                ui.input("Confirm new password").props(
                    "name='confirm_password' type='password' "
                    "autocomplete='new-password'"
                ).classes(INPUT_CLASSES)
                ui.button("Reset password", icon="lock_reset").props(
                    "type='submit'"
                ).classes(PRIMARY_BUTTON_CLASSES)
