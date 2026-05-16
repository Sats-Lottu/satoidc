import os

from fastapi import FastAPI

if os.getenv("SATOIDC_SETUP_WIZARD_MODE") == "1":
    app = FastAPI(title="Identity Service", version="0.1.0")
else:
    from nicegui import ui
    from starlette.middleware.sessions import SessionMiddleware

    from satoidc.auth.middleware import AuthMiddleware
    from satoidc.auth.oauth2 import config_oauth
    from satoidc.routes.app_routes import get_routers
    from satoidc.settings import ENV
    from satoidc.ui_theme import apply_theme

    app = FastAPI(title="Identity Service", version="0.1.0")
    app.add_middleware(AuthMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=ENV.SESSION_MIDDLEWARE_SECRET_KEY,
        same_site="lax",
        https_only=ENV.session_cookie_https_only,
        session_cookie="client_session",
    )

    app.config = {
        "OAUTH2_JWT_ISS": ENV.OAUTH2_JWT_ISS,
        "OAUTH2_JWT_KEY": ENV.OAUTH2_JWT_SECRET_KEY,
        "OAUTH2_JWT_ALG": ENV.OAUTH2_JWT_ALG,
        "OAUTH2_TOKEN_EXPIRES_IN": {
            "authorization_code": ENV.OAUTH2_TOKEN_EXPIRES_IN
        },
        "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
        "OAUTH2_ERROR_URIS": [
            (
                "invalid_client",
                f"https://developer.{ENV.DOMAIN}/errors#invalid-client",
            ),
        ],
    }

    config_oauth(app)

    for router in get_routers():
        app.include_router(router)

    apply_theme()

    ui.run_with(app, title="SatOIDC - Identity Service")
