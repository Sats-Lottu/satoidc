import logging
import os
from secrets import token_urlsafe
from typing import Annotated, Mapping

import segno
from fastapi import Depends, Form, Request
from nicegui import APIRouter, app, ui
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER

from satoidc.auth.lnurl import lnurl_auth_events, url_encode
from satoidc.enums import PermissionsEnum
from satoidc.models import LnurlAuthChallenge, Permission
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
from satoidc.runtime_config import RUNTIME_ENV_VARS, mask_secret
from satoidc.services.runtime_settings import (
    MUTABLE_BY_FIELD,
    RuntimeSettingSpec,
    RuntimeSettingValidationError,
    upsert_runtime_setting,
)
from satoidc.settings import ENV
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
)
from setup_wizard.apply import (
    InteractiveSetupAdminPayload,
    InteractiveSetupApplyResult,
    InteractiveSetupApplyStatus,
    apply_interactive_setup_admin,
    validate_interactive_setup_admin_payload,
)
from setup_wizard.bootstrap import (
    BootstrapStatus,
    validate_bootstrap_environment,
)
from setup_wizard.get_root import (
    authenticate_setup_admin_user,
    database_schema_ready,
    exists_setup_admin_user,
    has_active_setup_admin_permission,
    parse_root_user_id,
    setup_completed,
    setup_session,
)

router = APIRouter()
log = logging.getLogger(__name__)

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
    user = await authenticate_setup_admin_user(session, identifier, password)
    if user is None:
        return RedirectResponse(
            "/?setup_error=invalid-root-login",
            status_code=HTTP_303_SEE_OTHER,
        )

    request.session[SETUP_ROOT_USER_ID_KEY] = user.id.hex
    log.info(
        "Setup reconfiguration access granted",
        extra={
            "event_name": "setup.reconfigure_access_granted",
            "component": "setup_wizard",
            "actor": str(user.id),
            "auth_method": "password",
        },
    )
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
    if not await has_active_setup_admin_permission(session, user_id):
        return RedirectResponse(
            "/?setup_error=invalid-lnurl-root-login",
            status_code=HTTP_303_SEE_OTHER,
        )

    request.session[SETUP_ROOT_USER_ID_KEY] = str(user_id)
    log.info(
        "Setup reconfiguration access granted",
        extra={
            "event_name": "setup.reconfigure_access_granted",
            "component": "setup_wizard",
            "actor": str(user_id),
            "auth_method": "lnurl",
        },
    )
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
        if await has_active_setup_admin_permission(provided_session, user_id):
            return True
    else:
        async with setup_session() as session:
            if await has_active_setup_admin_permission(session, user_id):
                return True

    request.session.pop(SETUP_ROOT_USER_ID_KEY, None)
    return False


HIGH_IMPACT_RECONFIGURATION_FIELDS = {
    "EMAIL_PUBLIC_BASE_URL",
    "OAUTH2_JWT_ISS",
    "DATABASE_URL",
    "SYNC_DATABASE_URL",
    "OAUTH2_TOKEN_EXPIRES_IN",
    "OIDC_SIGNING_BACKEND",
}
SAFE_EDITABLE_RECONFIGURATION_FIELDS = {
    "SERVICE_NAME",
    "LNURL_K1_TTL_SECONDS",
    "OAUTH2_JWT_AUDIENCE",
    "OIDC_JWKS_CACHE_TTL_SECONDS",
    "EMAIL_SENDER_MODE",
    "SMTP_FROM_EMAIL",
}
CONFIRMABLE_HIGH_IMPACT_RECONFIGURATION_FIELDS = {
    "EMAIL_PUBLIC_BASE_URL",
    "OAUTH2_JWT_ISS",
    "OAUTH2_TOKEN_EXPIRES_IN",
    "OIDC_SIGNING_BACKEND",
}


def setup_reconfiguration_fields(
    env: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    values = {
        name.upper(): value
        for name, value in (os.environ if env is None else env).items()
    }
    fields: list[dict[str, object]] = []
    for spec in RUNTIME_ENV_VARS:
        names = [
            name for name in (spec.satoidc_name, spec.current_name) if name
        ]
        file_names = [f"{name}_FILE" for name in names if spec.supports_file]
        source = next((name for name in names if name in values), None)
        file_source = next(
            (name for name in file_names if name in values),
            None,
        )
        configured = source is not None or file_source is not None
        runtime_value = getattr(ENV, spec.field_name, "")
        value = values.get(source or "") if source else runtime_value
        if spec.secret:
            display_value = mask_secret(value or values.get(file_source or ""))
        elif file_source and not source:
            display_value = f"{file_source} file"
        else:
            display_value = value or "Not configured"
        mutable_spec = MUTABLE_BY_FIELD.get(spec.field_name)
        editable_fields = (
            SAFE_EDITABLE_RECONFIGURATION_FIELDS
            | CONFIRMABLE_HIGH_IMPACT_RECONFIGURATION_FIELDS
        )
        editable = (
            mutable_spec is not None
            and not configured
            and not spec.secret
            and spec.field_name in editable_fields
        )

        fields.append(
            {
                "name": spec.field_name,
                "key": mutable_spec.key if mutable_spec else "",
                "display_value": display_value,
                "value": runtime_value,
                "source": source or file_source or "default",
                "locked": configured,
                "editable": editable,
                "secret": spec.secret,
                "high_impact": (
                    spec.field_name in HIGH_IMPACT_RECONFIGURATION_FIELDS
                ),
            }
        )
    return fields


def _parse_reconfiguration_value(
    spec: RuntimeSettingSpec, raw_value: object
) -> object:
    value = str(raw_value or "").strip()
    if spec.value_type is int:
        return int(value)
    if spec.value_type is bool:
        return value.lower() in {"1", "true", "yes", "on"}
    if spec.value_type == bool | None:
        if not value:
            return None
        return value.lower() in {"1", "true", "yes", "on"}
    return value


def render_reconfiguration_field(
    field: dict[str, object], editable_inputs: dict[str, object]
):
    badge = "High impact" if field["high_impact"] else "Runtime"
    with ui.row().classes(
        "items-start gap-3 rounded-lg border border-white/10 "
        "bg-white/5 p-3 w-full"
    ):
        ui.icon("lock" if field["locked"] else "edit").classes(
            "text-sky-300"
        )
        with ui.column().classes("gap-1 w-full"):
            with ui.row().classes(
                "items-center justify-between gap-3 w-full"
            ):
                ui.label(str(field["name"])).classes("font-semibold")
                ui.label(badge).classes(
                    "text-xs uppercase tracking-wide text-slate-400"
                )
            if field["editable"]:
                editable_inputs[str(field["name"])] = ui.input(
                    "Value",
                    value=str(field["value"] or ""),
                ).classes(INPUT_CLASSES)
            else:
                ui.label(str(field["display_value"])).classes(
                    "font-mono text-sm break-all"
                )
            ui.label(f"Source: {field['source']}").classes(
                f"text-xs {MUTED_TEXT}"
            )


def render_high_impact_confirmation():
    with (
        ui.dialog() as confirmation_dialog,
        card(f"{DIALOG_CLASSES} max-w-lg mx-auto gap-4"),
    ):
        with ui.column().classes("gap-1"):
            ui.label("Confirm high-impact changes").classes(
                "text-xl font-semibold"
            )
            ui.label(
                "Issuer, public URL, database, token lifetime, and signing "
                "backend changes must be made outside the wizard and "
                "validated after restart."
            ).classes(MUTED_TEXT)
        with ui.column().classes("gap-2"):
            for item in (
                "Plan the value change in deployment configuration.",
                "Restart SatOIDC after updating the environment.",
                "Verify discovery, JWKS, token, and login behavior.",
            ):
                with ui.row().classes("items-start gap-2"):
                    ui.icon("check_circle").classes("text-emerald-400")
                    ui.label(item).classes("text-sm")
        with ui.row().classes(
            "gap-3 w-full justify-end max-sm:flex-col-reverse"
        ):
            ui.button(
                "Cancel",
                icon="close",
                on_click=confirmation_dialog.close,
            ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
            ui.button(
                "I understand",
                icon="verified",
                on_click=confirmation_dialog.close,
            ).classes(PRIMARY_BUTTON_CLASSES)

    ui.button(
        "Review high-impact changes",
        icon="warning",
        on_click=confirmation_dialog.open,
    ).props("outline").classes(SECONDARY_BUTTON_CLASSES)


def high_impact_reconfiguration_names(
    fields: list[dict[str, object]],
) -> list[str]:
    return [
        str(field["name"])
        for field in fields
        if field["editable"] and field["high_impact"]
    ]


def render_reconfiguration_panel():
    report = validate_bootstrap_environment()
    fields = setup_reconfiguration_fields()
    editable_inputs: dict[str, object] = {}
    high_impact_editable_names = high_impact_reconfiguration_names(fields)

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

            ui.separator().classes("opacity-20")
            with ui.column().classes("gap-2"):
                ui.label("Locked runtime settings").classes(
                    "text-lg font-semibold"
                )
                ui.label(
                    "Environment-controlled values are read-only in the "
                    "wizard. High-impact changes require operator action and "
                    "service restart."
                ).classes(f"text-sm {MUTED_TEXT}")

            for field in fields:
                render_reconfiguration_field(field, editable_inputs)

            high_impact_ack = None
            if high_impact_editable_names:
                with ui.column().classes(
                    "gap-2 rounded-lg border border-amber-400/30 "
                    "bg-amber-400/10 p-3"
                ):
                    ui.label("High-impact confirmation").classes(
                        "font-semibold"
                    )
                    ui.label(
                        "Saving these fields can invalidate clients, tokens, "
                        "or signing behavior: "
                        + ", ".join(high_impact_editable_names)
                    ).classes(f"text-sm {MUTED_TEXT}")
                    high_impact_ack = ui.checkbox(
                        "I understand the impact and have planned validation "
                        "after restart."
                    )

            async def save_reconfiguration():
                if high_impact_editable_names and not high_impact_ack.value:
                    ui.notify(
                        "Confirm high-impact changes before saving.",
                        type="warning",
                    )
                    return
                errors: list[str] = []
                async with setup_session() as session:
                    for field in fields:
                        if not field["editable"]:
                            continue
                        spec = MUTABLE_BY_FIELD[str(field["name"])]
                        input_element = editable_inputs[str(field["name"])]
                        try:
                            await upsert_runtime_setting(
                                session,
                                key=spec.key,
                                value=_parse_reconfiguration_value(
                                    spec, input_element.value
                                ),
                                production=ENV.is_production,
                                updated_by="setup-wizard",
                            )
                        except (
                            RuntimeSettingValidationError,
                            ValueError,
                        ) as exc:
                            errors.append(f"{field['name']}: {exc}")
                if errors:
                    for error in errors[:3]:
                        ui.notify(error, type="negative")
                    return
                log.info(
                    "Setup runtime settings updated",
                    extra={
                        "event_name": "setup.runtime_settings_updated",
                        "component": "setup_wizard",
                        "outcome": "updated",
                    },
                )
                ui.notify(
                    "Runtime settings saved. Restart SatOIDC to apply them.",
                    type="positive",
                )

            with ui.row().classes("gap-3 mt-4"):
                ui.button(
                    "Save editable settings",
                    icon="save",
                    on_click=save_reconfiguration,
                ).classes(PRIMARY_BUTTON_CLASSES)
                render_high_impact_confirmation()
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


def render_bootstrap_diagnostics_summary():
    report = validate_bootstrap_environment()

    with ui.column().classes("gap-3 w-full"):
        with ui.column().classes("gap-1"):
            ui.label("Setup diagnostics").classes("text-lg font-semibold")
            ui.label(
                "Review runtime checks before creating the initial root "
                "account."
            ).classes(f"text-sm {MUTED_TEXT}")

        for check in report.checks:
            status_ok = check.status == BootstrapStatus.OK
            status_color = "text-emerald-400" if status_ok else ERROR_TEXT
            with ui.row().classes(
                "items-start gap-3 rounded-lg border border-white/10 "
                "bg-white/5 p-3 w-full"
            ):
                ui.icon("check_circle" if status_ok else "error").classes(
                    status_color
                )
                with ui.column().classes("gap-1"):
                    ui.label(check.name).classes("font-semibold")
                    ui.label(check.message).classes(f"text-sm {MUTED_TEXT}")


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


def render_completed_setup_locked():
    with auth_shell("max-w-2xl"):
        with ui.column().classes("gap-4"):
            ui.label("Setup Locked").classes("text-2xl font-bold")
            ui.label(
                "This instance has already completed setup. Public root "
                "creation is no longer available."
            ).classes(MUTED_TEXT)
        with card("w-full gap-4"):
            ui.label("Next step").classes("text-xl font-semibold")
            ui.label(
                "Restart or open the main SatOIDC service and sign in with "
                "an existing administrator. Reconfiguration must happen from "
                "an authenticated admin context."
            ).classes(MUTED_TEXT)

            with ui.row().classes("gap-3 mt-4"):
                ui.button(
                    "Shut down wizard",
                    icon="close",
                    on_click=app.shutdown,
                ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
                ui.button(
                    "Retry checks",
                    icon="refresh",
                    on_click=ui.navigate.reload,
                ).classes(PRIMARY_BUTTON_CLASSES)


async def apply_initial_root_setup_form(
    *,
    username: str | None,
    email: str | None,
    password: str | None,
    password_confirmation: str | None,
) -> InteractiveSetupApplyResult:
    payload = InteractiveSetupAdminPayload(
        username=username or "",
        email=email or "",
        password=password or "",
        password_confirmation=password_confirmation or "",
    )
    async with setup_session() as db_session:
        return await apply_interactive_setup_admin(
            db_session,
            payload,
            actor="interactive-setup",
        )


def render_setup_completion_panel():
    with ui.column().classes("gap-1"):
        ui.label("Setup Complete").classes("text-2xl font-bold")
        ui.label(
            "The initial root account was created and public setup is now "
            "locked."
        ).classes(MUTED_TEXT)
    with ui.row().classes(
        "items-start gap-3 rounded-lg border border-emerald-500/30 "
        "bg-emerald-500/10 p-3"
    ):
        ui.icon("verified").classes("text-emerald-500 text-2xl")
        with ui.column().classes("gap-1"):
            ui.label("Root bootstrap finished.").classes(
                "font-semibold text-emerald-700 dark:text-emerald-300"
            )
            ui.label(
                "Restart or open the main SatOIDC service and sign in with "
                "the account you just created."
            ).classes(f"text-sm {MUTED_TEXT}")
    with ui.row().classes("gap-3 mt-2 w-full justify-end max-sm:flex-col"):
        ui.button(
            "Retry checks",
            icon="refresh",
            on_click=ui.navigate.reload,
        ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
        ui.button(
            "Shut down wizard",
            icon="close",
            on_click=app.shutdown,
        ).classes(PRIMARY_BUTTON_CLASSES)


def initial_root_form_state_from_result(
    result: InteractiveSetupApplyResult,
) -> dict[str, object]:
    if result.status == InteractiveSetupApplyStatus.APPLIED:
        return {"errors": {}, "completed": True, "message": ""}
    return {
        "errors": result.errors,
        "completed": False,
        "message": result.message,
    }


def initial_root_review_from_payload(
    payload: InteractiveSetupAdminPayload,
) -> dict[str, str]:
    return {
        "username": payload.username.strip().lower(),
        "email": payload.email.strip().lower(),
        "password": "********",
    }


def render_root_login(request: Request):
    setup_error = request.query_params.get("setup_error")
    with auth_shell():
        with responsive_grid(2, "gap-6 items-stretch"):
            auth_context_panel(
                eyebrow="Setup Access",
                title="Root credentials protect service reconfiguration.",
                body=(
                "After initial setup, this wizard remains available for "
                "runtime checks but requires an administrator account or "
                "linked Lightning wallet."
            ),
            features=[
                (
                    "admin_panel_settings",
                    "Admin only",
                    "Only active admin/root users can reach setup checks.",
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
                    ui.label("Setup Access Required").classes(
                        "text-2xl font-bold"
                    )
                    ui.label(
                        "Sign in with admin credentials to access setup."
                    ).classes(MUTED_TEXT)
                if setup_error:
                    ui.label("Invalid admin credentials.").classes(ERROR_TEXT)
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
            has_root_permission = await has_active_setup_admin_permission(
                db_session,
                user_id,
            )

        if not has_root_permission:
            ui.notify(
                "Lightning wallet is not an admin account.",
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


def render_initial_root_admin_form():
    form_state: dict[str, object] = {
        "errors": {},
        "completed": False,
        "message": "",
        "review": False,
        "payload": None,
    }

    @ui.refreshable
    def root_form():
        if form_state["completed"]:
            render_setup_completion_panel()
            return

        if form_state["review"]:
            render_initial_root_review(form_state, root_form)
            return

        render_bootstrap_diagnostics_summary()

        with ui.column().classes("gap-1 mt-2"):
            ui.label("Create Root").classes("text-xl font-semibold")
            ui.label("Register the initial administrator account.").classes(
                MUTED_TEXT
            )

        errors = form_state["errors"]
        if form_state["message"]:
            ui.label(str(form_state["message"])).classes(ERROR_TEXT)

        payload = form_state.get("payload")
        has_payload = isinstance(payload, InteractiveSetupAdminPayload)
        username_value = (
            payload.username if has_payload else None
        )
        email_value = payload.email if has_payload else None
        password_value = payload.password if has_payload else None
        confirm_value = (
            payload.password_confirmation if has_payload else None
        )

        login_field = (
            ui.input(
                "Login",
                value=username_value,
                validation={"Invalid login!": is_valid_login},
            )
            .classes(INPUT_CLASSES)
            .tooltip("Lowercase letters and numbers, 6-30 characters")
        )
        render_initial_root_field_error(errors, "username")

        email_field = (
            ui.input(
                "Email",
                value=email_value,
                validation={"Invalid email!": is_valid_email},
            )
            .props("type=email")
            .classes(INPUT_CLASSES)
        ).tooltip("Enter a valid email address")
        render_initial_root_field_error(errors, "email")

        password_field = (
            ui.input(
                "Password",
                value=password_value,
                password=True,
                password_toggle_button=True,
                validation={
                    "Weak password!": lambda value: is_valid_password(
                        value or ""
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
        render_initial_root_field_error(errors, "password")

        confirm_field = ui.input(
            "Confirm password",
            value=confirm_value,
            password=True,
            password_toggle_button=True,
            validation={
                "Not same password!": lambda value: (
                    password_field.value == value
                )
            },
        ).classes(INPUT_CLASSES)
        for field in (
            "password_confirmation",
            "admin",
            "setup_lock",
            "apply",
        ):
            render_initial_root_field_error(errors, field)

        async def submit():
            payload = InteractiveSetupAdminPayload(
                username=login_field.value or "",
                email=email_field.value or "",
                password=password_field.value or "",
                password_confirmation=confirm_field.value or "",
            )
            errors = await validate_interactive_setup_admin_payload(payload)
            if errors:
                form_state.update(
                    {
                        "errors": errors,
                        "message": (
                            "Interactive setup admin payload is invalid."
                        ),
                        "payload": payload,
                        "review": False,
                    }
                )
                ui.notify("Review the highlighted fields.", type="negative")
            else:
                form_state.update(
                    {
                        "errors": {},
                        "message": "",
                        "payload": payload,
                        "review": True,
                    }
                )
            root_form.refresh()

        with ui.row().classes(
            "gap-3 mt-2 w-full justify-end max-sm:flex-col"
        ):
            ui.button(
                "Review setup",
                icon="fact_check",
                on_click=submit,
            ).classes(f"w-full {PRIMARY_BUTTON_CLASSES}")

    root_form()


def render_initial_root_review(form_state: dict[str, object], root_form):
    payload = form_state.get("payload")
    if not isinstance(payload, InteractiveSetupAdminPayload):
        form_state["review"] = False
        return

    review = initial_root_review_from_payload(payload)

    with ui.column().classes("gap-1"):
        ui.label("Review setup").classes("text-2xl font-bold")
        ui.label(
            "Confirm the initial root account before applying setup."
        ).classes(MUTED_TEXT)

    with ui.column().classes(
        "gap-3 rounded-lg border border-white/10 bg-white/5 p-3 w-full"
    ):
        for label, value in (
            ("Login", review["username"]),
            ("Email", review["email"]),
            ("Password", review["password"]),
        ):
            with ui.row().classes(
                "items-center justify-between gap-3 w-full max-sm:flex-col "
                "max-sm:items-start"
            ):
                ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                ui.label(value).classes(
                    "font-mono text-sm break-all text-right max-sm:text-left"
                )

    ui.label(
        "After confirmation, public setup is locked and the completion "
        "screen offers shutdown."
    ).classes(f"text-sm {MUTED_TEXT}")

    async def confirm():
        result = await apply_initial_root_setup_form(
            username=payload.username,
            email=payload.email,
            password=payload.password,
            password_confirmation=payload.password_confirmation,
        )
        form_state.update(initial_root_form_state_from_result(result))
        if form_state["completed"]:
            form_state.update({"payload": None, "review": False})
            ui.notify("Root user created.", type="positive")
        else:
            form_state.update({"review": False})
            ui.notify("Setup could not be applied.", type="negative")
        root_form.refresh()

    def back_to_form():
        form_state.update({"review": False, "errors": {}, "message": ""})
        root_form.refresh()

    with ui.row().classes(
        "gap-3 mt-2 w-full justify-end max-sm:flex-col-reverse"
    ):
        ui.button(
            "Back",
            icon="arrow_back",
            on_click=back_to_form,
        ).props("outline").classes(SECONDARY_BUTTON_CLASSES)
        ui.button(
            "Create root account",
            icon="admin_panel_settings",
            on_click=confirm,
        ).classes(PRIMARY_BUTTON_CLASSES)


def render_initial_root_field_error(errors: object, field: str):
    if not isinstance(errors, dict) or field not in errors:
        return
    ui.label(str(errors[field])).classes(f"text-sm {ERROR_TEXT}")


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
                render_initial_root_admin_form()
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

    if await setup_completed():
        if await exists_setup_admin_user():
            await render_existing_root_setup(request)
        else:
            render_completed_setup_locked()
        return

    if await exists_setup_admin_user():
        await render_existing_root_setup(request)
        return

    render_initial_root_setup(request)
