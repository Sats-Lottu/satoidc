#!/usr/bin/env python3
import argparse
import logging
import os
import time
from typing import Any

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Request
from nicegui import app, ui
from starlette.responses import RedirectResponse

DEFAULT_PROVIDER_URL = "http://localhost:8000"
DEFAULT_SCOPE = "openid email profile"
DEFAULT_STORAGE_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a confidential NiceGUI OIDC client for SatOIDC."
    )
    parser.add_argument(
        "--client-id",
        default=os.getenv("SATOIDC_CLIENT_ID"),
        help="OAuth client_id. Can also be set with SATOIDC_CLIENT_ID.",
    )
    parser.add_argument(
        "--client-secret",
        default=os.getenv("SATOIDC_CLIENT_SECRET"),
        help=(
            "OAuth client_secret. Can also be set with "
            "SATOIDC_CLIENT_SECRET."
        ),
    )
    parser.add_argument(
        "--provider-url",
        default=os.getenv("SATOIDC_PROVIDER_URL", DEFAULT_PROVIDER_URL),
        help="SatOIDC issuer base URL.",
    )
    parser.add_argument(
        "--scope",
        default=os.getenv("SATOIDC_SCOPE", DEFAULT_SCOPE),
        help="OIDC scopes to request.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("SATOIDC_CLIENT_HOST", "localhost"),
    )
    parser.add_argument(
        "--port",
        default=int(os.getenv("SATOIDC_CLIENT_PORT", "8001")),
        type=int,
    )
    parser.add_argument(
        "--storage-secret",
        default=os.getenv(
            "SATOIDC_EXAMPLE_STORAGE_SECRET", DEFAULT_STORAGE_SECRET
        ),
        help="NiceGUI per-user storage signing secret.",
    )
    parsed = parser.parse_args()
    if not parsed.client_id:
        parser.error("--client-id or SATOIDC_CLIENT_ID is required")
    if not parsed.client_secret:
        parser.error("--client-secret or SATOIDC_CLIENT_SECRET is required")
    parsed.provider_url = parsed.provider_url.rstrip("/")
    return parsed


args = parse_args()
CLIENT_ID = args.client_id.strip()
PROVIDER_URL = args.provider_url
oauth = OAuth()
oauth.register(
    name="satoidc",
    server_metadata_url=(
        f"{PROVIDER_URL}/.well-known/openid-configuration"
    ),
    client_id=CLIENT_ID,
    client_secret=args.client_secret,
    client_kwargs={
        "scope": args.scope,
    },
)


@ui.page("/")
async def main(request: Request) -> RedirectResponse | None:
    user_info = app.storage.user.get("user_info", {})
    oauth_error = app.storage.user.pop("oauth_error", None)

    if oauth_error:
        _render_error(oauth_error)
        return None

    if not _is_valid(user_info):
        app.storage.user.pop("user_info", None)
        return await oauth.satoidc.authorize_redirect(
            request,
            request.url_for("auth"),
        )

    _render_user(user_info)
    return None


def logout() -> None:
    app.storage.user.pop("user_info", None)
    ui.navigate.to("/")


@app.get("/auth/callback")
async def auth(request: Request) -> RedirectResponse:
    try:
        token = await oauth.satoidc.authorize_access_token(request)
        user_info = token.get("userinfo", {})
        if _is_valid(user_info):
            app.storage.user["user_info"] = user_info
        else:
            app.storage.user["oauth_error"] = (
                "The provider returned a token, but its claims did not match "
                "this client configuration."
            )
    except OAuthError as exc:
        logging.exception("could not authorize access token")
        app.storage.user["oauth_error"] = exc.error or str(exc)
    except Exception as exc:
        logging.exception("could not authorize access token")
        app.storage.user["oauth_error"] = str(exc)
    return RedirectResponse("/")


def _is_valid(user_info: dict[str, Any]) -> bool:
    try:
        expires_at = int(user_info.get("exp", 0))
        return all(
            [
                expires_at > int(time.time()),
                _audience_matches(user_info.get("aud")),
                user_info.get("iss") == PROVIDER_URL,
            ]
        )
    except (TypeError, ValueError):
        return False


def _audience_matches(audience: str | list[str] | None) -> bool:
    if isinstance(audience, str):
        return audience == CLIENT_ID
    if isinstance(audience, list):
        return CLIENT_ID in audience
    return False


def _render_user(user_info: dict[str, Any]) -> None:
    ui.query("body").classes("bg-slate-950 text-slate-100")
    with ui.column().classes("mx-auto w-full max-w-2xl gap-4 px-4 py-8"):
        ui.label("SatOIDC confidential client").classes(
            "text-2xl font-bold"
        )
        with ui.card().classes(
            "w-full gap-3 rounded-lg border border-slate-700 "
            "bg-slate-900/80 p-5"
        ):
            display_name = user_info.get("name") or user_info.get("sub")
            ui.label(f"Welcome {display_name}").classes(
                "text-xl font-semibold"
            )
            ui.label(f"Issuer: {user_info.get('iss')}").classes(
                "text-sm text-slate-400"
            )
            ui.label(f"Subject: {user_info.get('sub')}").classes(
                "break-all text-sm text-slate-400"
            )
            if user_info.get("email"):
                ui.label(f"Email: {user_info['email']}").classes(
                    "text-sm text-slate-400"
                )
            ui.button("Logout", icon="logout", on_click=logout).props(
                "unelevated no-caps color=primary"
            )


def _render_error(message: str) -> None:
    ui.query("body").classes("bg-slate-950 text-slate-100")
    with ui.column().classes("mx-auto w-full max-w-2xl gap-4 px-4 py-8"):
        ui.label("Authorization failed").classes("text-2xl font-bold")
        with ui.card().classes(
            "w-full gap-3 rounded-lg border border-red-900/60 "
            "bg-slate-900/80 p-5"
        ):
            ui.label(message).classes("break-words text-sm text-red-300")
            ui.button(
                "Try again",
                icon="login",
                on_click=lambda: ui.navigate.to("/"),
            ).props("unelevated no-caps color=primary")


ui.run(host=args.host, port=args.port, storage_secret=args.storage_secret)
