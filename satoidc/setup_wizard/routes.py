from secrets import token_urlsafe
from typing import Annotated

import segno
from fastapi import Depends, Form, Request
from nicegui import APIRouter, app, ui
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER

from satoidc.auth.lnurl import lnurl_auth_events, url_encode
from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import LnurlAuthChallenge, Permission, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    DIALOG_CLASSES,
    ERROR_TEXT,
    INPUT_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    app_header,
    auth_context_panel,
    auth_shell,
    card,
    responsive_grid,
)
from satoidc.settings import ENV
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
    validate_registration_form,
)
from setup_wizard.bootstrap import (
    BootstrapStatus,
    validate_bootstrap_environment,
)
from setup_wizard.get_root import (
    authenticate_root_user,
    database_schema_ready,
    exists_root_user,
    has_active_root_permission,
    parse_root_user_id,
    setup_session,
)

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]
SETUP_ROOT_USER_ID_KEY = "setup_root_user_id"
LNURL_ROOT_LOGIN_TICKET_PREFIX = "setup:lnurl-root-login:"


def redirect_to_root() -> RedirectResponse:
    return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)


def store_lnurl_root_login_ticket(user_id) -> str:
    ticket = token_urlsafe(32)
    app.storage.general[LNURL_ROOT_LOGIN_TICKET_PREFIX + ticket] = str(user_id)
    return ticket


def pop_lnurl_root_login_ticket(ticket: str | None) -> str | None:
    if not ticket:
        return None
    return app.storage.general.pop(
        LNURL_ROOT_LOGIN_TICKET_PREFIX + ticket,
        None,
    )


@router.post("/setup/root-login")
async def setup_root_login(
    request: Request,
    session: Session,
    identifier: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> RedirectResponse:
    user = await authenticate_root_user(session, identifier, password)
    if user is None:
        return RedirectResponse(
            "/?setup_error=invalid-root-login",
            status_code=HTTP_303_SEE_OTHER,
        )

    request.session[SETUP_ROOT_USER_ID_KEY] = user.id.hex
    return redirect_to_root()


@router.get("/setup/logout")
async def setup_logout(request: Request) -> RedirectResponse:
    request.session.pop(SETUP_ROOT_USER_ID_KEY, None)
    return redirect_to_root()


@router.get("/setup/complete-lnurl-login")
async def complete_lnurl_root_login(
    request: Request,
    session: Session,
    ticket: str | None = None,
) -> RedirectResponse:
    user_id = pop_lnurl_root_login_ticket(ticket)
    if not await has_active_root_permission(session, user_id):
        return RedirectResponse(
            "/?setup_error=invalid-lnurl-root-login",
            status_code=HTTP_303_SEE_OTHER,
        )

    request.session[SETUP_ROOT_USER_ID_KEY] = str(user_id)
    return redirect_to_root()


def finalizing_setup():
    ui.notify("Root user created!", type="positive")
    ui.notify("Finalizing setup...", type="positive")
    ui.timer(0.8, app.shutdown, once=True)


def setup_header():
    app_header(
        nav=[("GitHub", "https://github.com/Sats-Lottu/satoidc", "github")]
    )


async def stored_root_has_access(
    session_or_request: Session | Request,
    request: Request | None = None,
) -> bool:
    provided_session = session_or_request if request is not None else None
    request = request or session_or_request
    user_id = parse_root_user_id(request.session.get(SETUP_ROOT_USER_ID_KEY))
    if user_id is None:
        request.session.pop(SETUP_ROOT_USER_ID_KEY, None)
        return False

    if provided_session is not None:
        if await has_active_root_permission(provided_session, user_id):
            return True
    else:
        async with setup_session() as session:
            if await has_active_root_permission(session, user_id):
                return True

    request.session.pop(SETUP_ROOT_USER_ID_KEY, None)
    return False


def render_reconfiguration_panel():
    report = validate_bootstrap_environment()

    with auth_shell("max-w-2xl"):
        with ui.column().classes("gap-4"):
            ui.label("Service Setup").classes("text-2xl font-bold")
            ui.label(
                "Review the runtime checks before restarting or changing "
                "deployment configuration."
            ).classes(MUTED_TEXT)
        with card("w-full gap-4"):
            ui.label("Bootstrap checks").classes("text-xl font-semibold")
            ui.label(
                "Root authentication is active. Update environment values "
                "outside the app, then restart services as needed."
            ).classes(MUTED_TEXT)

            for check in report.checks:
                status_color = (
                    "text-emerald-400"
                    if check.status == BootstrapStatus.OK
                    else ERROR_TEXT
                )
                with ui.row().classes("items-start gap-3 w-full"):
                    ui.icon(
                        "check_circle"
                        if check.status == BootstrapStatus.OK
                        else "error"
                    ).classes(status_color)
                    with ui.column().classes("gap-1"):
                        ui.label(check.name).classes("font-semibold")
                        ui.label(check.message).classes(
                            f"text-sm {MUTED_TEXT}"
                        )

            with ui.row().classes("gap-3 mt-4"):
                ui.button(
                    "Shut down wizard",
                    icon="close",
                    on_click=app.shutdown,
                ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
                ui.button(
                    "Sign out",
                    icon="logout",
                    on_click=lambda: ui.navigate.to("/setup/logout"),
                ).classes(PRIMARY_BUTTON_CLASSES)


def render_database_setup_required():
    with auth_shell("max-w-2xl"):
        with ui.column().classes("gap-4"):
            ui.label("Database Setup Required").classes(
                "text-2xl font-bold"
            )
            ui.label(
                "The database is reachable, but SatOIDC tables are missing. "
                "Apply migrations before creating or authenticating root "
                "users."
            ).classes(MUTED_TEXT)
        with card("w-full gap-4"):
            ui.label("Apply migrations").classes("text-xl font-semibold")
            ui.label(
                "Run this command from the project package directory, then "
                "reload the setup wizard."
            ).classes(MUTED_TEXT)
            ui.code("poetry run alembic upgrade head").classes("w-full")

            with ui.row().classes("gap-3 mt-4"):
                ui.button(
                    "Shut down wizard",
                    icon="close",
                    on_click=app.shutdown,
                ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
                ui.button(
                    "Retry",
                    icon="refresh",
                    on_click=ui.navigate.reload,
                ).classes(PRIMARY_BUTTON_CLASSES)


def render_root_login(request: Request):
    setup_error = request.query_params.get("setup_error")
    with auth_shell():
        with responsive_grid(2, "gap-6 items-stretch"):
            auth_context_panel(
                eyebrow="Setup Access",
                title="Root credentials protect service reconfiguration.",
                body=(
                    "After initial setup, this wizard remains available for "
                    "runtime checks but requires a root account or linked "
                    "Lightning wallet."
                ),
                features=[
                    (
                        "admin_panel_settings",
                        "Root only",
                        "Only active root users can reach setup checks.",
                    ),
                    (
                        "qr_code",
                        "Lightning access",
                        "Use the floating QR action for linked root wallets.",
                    ),
                    (
                        "lock",
                        "Isolated session",
                        "Setup uses its own session cookie.",
                    ),
                ],
            )
            with card("max-w-lg w-full mx-auto items-stretch gap-4"):
                with ui.column().classes("gap-1"):
                    ui.label("Root Access Required").classes(
                        "text-2xl font-bold"
                    )
                    ui.label(
                        "Sign in with root credentials to access setup."
                    ).classes(MUTED_TEXT)
                if setup_error:
                    ui.label("Invalid root credentials.").classes(ERROR_TEXT)
                with (
                    ui.element("form")
                    .props('method="post" action="/setup/root-login"')
                    .classes("flex flex-col gap-3 w-full")
                ):
                    ui.input("Login or email").props(
                        "name='identifier' autocomplete='username'"
                    ).classes(INPUT_CLASSES)
                    ui.input(
                        "Password",
                        password=True,
                        password_toggle_button=True,
                    ).props(
                        "name='password' autocomplete='current-password'"
                    ).classes(INPUT_CLASSES)

                    with ui.row().classes(
                        "gap-3 w-full justify-end max-sm:flex-col-reverse"
                    ):
                        ui.button(
                            "Shut down",
                            icon="close",
                            on_click=app.shutdown,
                        ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
                        ui.button("Continue", icon="login").props(
                            "type='submit'"
                        ).classes(PRIMARY_BUTTON_CLASSES)


async def render_existing_root_setup(request: Request):
    lnurl_auth_login_root = LNURLAuthQRLoginRoot(
        base_url=str(request.base_url)
    )
    ui.timer(
        ENV.LNURL_K1_TTL_SECONDS,
        lnurl_auth_login_root.refresh_qrcode,
    )

    @lnurl_auth_events.subscribe
    async def _login_event_handler(data: dict):
        if data.get("k1") != lnurl_auth_login_root.k1:
            return

        user_id = data.get("user_id")
        if not user_id:
            ui.notify("Lightning login failed.", type="negative")
            return

        async with setup_session() as db_session:
            has_root_permission = await has_active_root_permission(
                db_session,
                user_id,
            )

        if not has_root_permission:
            ui.notify(
                "Lightning wallet is not a root account.",
                type="negative",
            )
            return

        ticket = store_lnurl_root_login_ticket(user_id)
        ui.navigate.to(f"/setup/complete-lnurl-login?ticket={ticket}")

    with (
        ui.dialog() as login_dialog,
        card(f"{DIALOG_CLASSES} max-w-lg mx-auto items-center gap-4"),
    ):
        lnurl_auth_login_root.qrcode()
        ui.button("Close", icon="close", on_click=login_dialog.close).props(
            "outline"
        ).classes(SECONDARY_BUTTON_CLASSES)

    if not await stored_root_has_access(request):
        render_root_login(request)
        with ui.page_sticky(x_offset=18, y_offset=18):
            ui.button(icon="qr_code", on_click=login_dialog.open).props(
                "fab"
            )
        return

    render_reconfiguration_panel()


class LNURLAuthQRRegisterRoot:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.k1 = None
        self.action = "register"

    async def refresh_qrcode(self):
        challenge = LnurlAuthChallenge(action=self.action)
        async with setup_session() as session:
            session.add(challenge)
            await session.commit()
            await session.refresh(challenge)
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
                "w-64 h-64"
            ).tooltip(
                "Scan with your Lightning Wallet to register as root user"
            )
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


class LNURLAuthQRLoginRoot:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.k1 = None
        self.action = "login"

    async def refresh_qrcode(self):
        challenge = LnurlAuthChallenge(action=self.action)
        async with setup_session() as session:
            session.add(challenge)
            await session.commit()
            await session.refresh(challenge)
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
                "w-64 h-64"
            ).tooltip("Scan with a root Lightning Wallet to access setup")
        ui.label(lnurl_auth).classes(
            "mt-2 w-full break-all text-xs text-center"
        ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
            "click",
            lambda e: ui.notify("LNURL copied to clipboard!", type="positive"),
        ).tooltip("Click to copy")


def render_initial_root_setup(request: Request):
    lnurl_auth_register_root = LNURLAuthQRRegisterRoot(
        base_url=str(request.base_url)
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

            async with setup_session() as db_session:
                db_session.add(permission)
                await db_session.commit()
            finalizing_setup()

    with (
        ui.dialog() as dialog,
        card(f"{DIALOG_CLASSES} max-w-lg mx-auto items-center gap-4"),
    ):
        lnurl_auth_register_root.qrcode()
        ui.button("Close", icon="close", on_click=dialog.close).props(
            "outline"
        ).classes(SECONDARY_BUTTON_CLASSES)
    # Refresh QR code every 60 seconds to prevent reuse of old challenges

    with auth_shell():
        with responsive_grid(2, "gap-6 items-stretch"):
            auth_context_panel(
                eyebrow="Initial Setup",
                title="Create the first SatOIDC root account.",
                body=(
                    "The setup wizard creates the first root identity and "
                    "keeps later service setup behind root credentials."
                ),
                features=[
                    (
                        "verified_user",
                        "Root bootstrap",
                        "Creates the first account with root permission.",
                    ),
                    (
                        "qr_code",
                        "Wallet option",
                        "Use the floating QR action to bootstrap with LNURL.",
                    ),
                    (
                        "security",
                        "Controlled startup",
                        "The wizard shuts down after successful setup.",
                    ),
                ],
            )
            with card("max-w-lg w-full mx-auto items-stretch gap-4"):
                with ui.column().classes("gap-1"):
                    ui.label("Create Root").classes("text-2xl font-bold")
                    ui.label(
                        "Register the initial administrator account."
                    ).classes(MUTED_TEXT)

                login_field = (
                    ui.input(
                        "Login",
                        validation={"Invalid login!": is_valid_login},
                    )
                    .classes(INPUT_CLASSES)
                    .tooltip(
                        "Lowercase letters and numbers, 6-30 characters"
                    )
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
                                is_valid_password(v)
                                if len(v) >= 0
                                else True
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
                _confirm = ui.input(
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
                    permission = Permission(
                        permission_type=PermissionsEnum.ROOT,
                        granted_by=None,
                        reason="Initial root user created via setup wizard",
                        expiration_date=None,
                        user_id=user.id,
                    )
                    async with setup_session() as db_session:
                        db_session.add(user)
                        db_session.add(permission)
                        await db_session.commit()
                        await db_session.refresh(user)
                    finalizing_setup()

                with ui.row().classes(
                    "gap-3 mt-2 w-full justify-end max-sm:flex-col"
                ):
                    ui.button(
                        "Create account",
                        icon="admin_panel_settings",
                        on_click=submit,
                    ).classes(f"w-full {PRIMARY_BUTTON_CLASSES}")
    with ui.page_sticky(x_offset=18, y_offset=18):
        ui.button(icon="qr_code", on_click=dialog.open).props("fab").classes(
            PRIMARY_BUTTON_CLASSES
        )


@router.page("/", dark=True)
async def set_root(request: Request):
    ui.add_head_html(
        '<link href="https://unpkg.com/eva-icons@1.1.3/style/eva-icons.css"'
        ' rel="stylesheet" />',
        shared=True,
    )

    if not await database_schema_ready():
        render_database_setup_required()
        return

    if await exists_root_user():
        await render_existing_root_setup(request)
        return

    render_initial_root_setup(request)
