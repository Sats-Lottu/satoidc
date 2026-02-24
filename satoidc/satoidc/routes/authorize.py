from secrets import token_urlsafe

from authlib.oauth2 import OAuth2Error
from fastapi import Request
from nicegui import APIRouter, ui

from satoidc.auth.oauth2 import authorization

router = APIRouter()


@router.page("/authorize")
async def authorize_get(request: Request):
    # valida request de consentimento
    try:
        _grant = authorization.validate_consent_request(request=request)
    except OAuth2Error as error:
        ui.notify(str(dict(error.get_body())))

    # CSRF
    csrf = token_urlsafe(32)
    request.session["csrf_token"] = csrf

    ui.label("Authorize Application").classes("text-2xl font-bold")
    action = "/oauth/authorize" + (
        ("?" + request.url.query) if request.url.query else ""
    )
    # 🔐 FORM: sem depender de query na action
    with (
        ui.element("form")
        .props(f"method='post' action='{action}'")
        .classes("mt-4")
    ):
        # CSRF + decision
        ui.element("input").props(
            f"type='hidden' name='csrf_token' value='{csrf}'"
        )

        # ✅ Reenvia TODOS os parâmetros OAuth como hidden (inclui client_id)
        for k, v in request.query_params.items():
            ui.element("input").props(f"type='hidden' name='{k}' value='{v}'")

        with ui.row().classes("gap-3"):
            ui.button("Approve").props(
                'type="submit" name="decision" value="approve"'
            )
            ui.button("Deny").props(
                'type="submit" name="decision" value="deny" outline'
            )
