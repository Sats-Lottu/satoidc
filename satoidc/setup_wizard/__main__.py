from nicegui import app, ui
from starlette.middleware.sessions import SessionMiddleware

from satoidc.routes.lnurl_auth import router as lnurl_auth_router
from satoidc.settings import ENV

from .routes import router


def main():
    app.add_middleware(
        SessionMiddleware,
        secret_key=ENV.SESSION_MIDDLEWARE_SECRET_KEY,
        same_site="lax",
        https_only=ENV.session_cookie_https_only,
        session_cookie="setup_session",
    )
    app.include_router(router)
    app.include_router(lnurl_auth_router)
    ui.run(reload=False, port=8000)


if __name__ == "__main__":
    main()
