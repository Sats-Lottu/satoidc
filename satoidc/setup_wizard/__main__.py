import asyncio

from nicegui import app, ui
from satoidc.routes.lnurl_auth import router as lnurl_auth_router

from .get_root import exists_root_user
from .routes import router


def main():
    exists_root = asyncio.run(exists_root_user())
    if not exists_root:
        app.include_router(router)
        app.include_router(lnurl_auth_router)
        ui.run(reload=False, port=8000)


if __name__ == "__main__":
    main()
