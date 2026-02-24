#!/usr/bin/env python3
import logging
import time

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Request
from nicegui import app, ui
from starlette.responses import RedirectResponse

CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-secret"
oauth = OAuth()
oauth.register(
    name="satoidc",
    server_metadata_url="http://localhost:8000/oauth/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={
        "scope": "openid email profile",
    },
)


@ui.page("/")
async def main(request: Request) -> RedirectResponse | None:
    user_info = app.storage.user.get("user_info", {})
    if not _is_valid(user_info):
        app.storage.user.pop("user_info", None)
        return await oauth.satoidc.authorize_redirect(
            request,
            request.url_for("satoidc"),
        )

    ui.label(f"Welcome {user_info.get('name', '')}!")
    ui.button("Logout", on_click=logout)
    return None


def logout() -> None:
    del app.storage.user["user_info"]
    ui.navigate.to("/")


@app.get("/auth/callback")
async def auth(request: Request) -> RedirectResponse:
    try:
        user_info = (
            await oauth.satoidc.authorize_access_token(request)
        ).get("userinfo", {})
        if _is_valid(user_info):
            app.storage.user["user_info"] = user_info
        print("User info:", user_info)
    except (OAuthError, Exception):
        logging.exception("could not authorize access token")
    return RedirectResponse("/")


def _is_valid(user_info: dict) -> bool:
    try:
        return all(
            [
                int(user_info.get("exp", 0)) > int(time.time()),
                user_info.get("aud") == [CLIENT_ID],
                user_info.get("iss")
                in {"http://localhost:8000", "localhost:8000"},
            ]
        )
    except Exception:
        return False


ui.run(
    host="localhost",
    port=8001,
    storage_secret="CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
)
