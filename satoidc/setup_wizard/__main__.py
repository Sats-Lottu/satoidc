import os

os.environ["SATOIDC_SETUP_WIZARD_MODE"] = "1"

import uvicorn
from fastapi import FastAPI, Request
from nicegui import ui
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from satoidc.routes.lnurl_auth import router as lnurl_auth_router
from satoidc.settings import ENV
from satoidc.ui_theme import apply_theme

from .routes import router


async def redirect_to_setup(_request: Request) -> RedirectResponse:
    return RedirectResponse("/", status_code=307)


def create_app(*, mount_ui: bool = True) -> FastAPI:
    setup_app = FastAPI(title="SatOIDC Setup Wizard", version="0.1.0")
    setup_app.add_middleware(
        SessionMiddleware,
        secret_key=ENV.SESSION_MIDDLEWARE_SECRET_KEY,
        same_site="lax",
        https_only=ENV.session_cookie_https_only,
        session_cookie="setup_session",
    )
    setup_app.include_router(router)
    setup_app.include_router(lnurl_auth_router)
    if mount_ui:
        apply_theme()
        ui.run_with(setup_app, title="SatOIDC - Setup Wizard", dark=True)
    setup_app.add_api_route(
        "/{path:path}",
        redirect_to_setup,
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        include_in_schema=False,
    )
    return setup_app


def main():
    uvicorn.run(create_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
