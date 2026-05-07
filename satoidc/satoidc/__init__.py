from fastapi import FastAPI
from nicegui import ui
from starlette.middleware.sessions import SessionMiddleware

from satoidc.auth.middleware import AuthMiddleware
from satoidc.auth.oauth2 import config_oauth
from satoidc.routes import routers
from satoidc.settings import ENV
from satoidc.ui_theme import apply_theme

app = FastAPI(title="Identity Service", version="0.1.0")
app.add_middleware(AuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=ENV.SESSION_MIDDLEWARE_SECRET_KEY,
    same_site="lax",
    https_only=False,
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

for router in routers:
    app.include_router(router)

apply_theme()

ui.run_with(app, title="SatOIDC - Identity Service")
