import logging
from urllib.parse import quote, urlencode

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)

PUBLIC_PREFIXES = (
    "/_nicegui",  # assets internos
    "/oauth",  # tudo de OIDC
    "/api",  # APIs públicas (token, callbacks, etc.)
    "/auth/lnurl",  # endpoints de LNURL auth
    "/.well-known",  # OIDC/OAuth discovery documents
)

PUBLIC_EXACT = {
    "/register",
    "/login",
    "/logout",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/health",
    "/forbidden",  # página de acesso negado
    "/",
}


def is_public_path(path: str) -> bool:
    if path in PUBLIC_EXACT:
        return True

    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in PUBLIC_PREFIXES
    )


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # noqa: PLR6301

        path = request.url.path

        if is_public_path(path):
            return await call_next(request)

        user_id = request.session.get("user_id")
        if not user_id:
            log.info(
                "Missing session for protected route",
                extra={
                    "event_name": "auth.session_missing",
                    "component": "auth_middleware",
                    "outcome": "redirect",
                    "path": path,
                },
            )
            full = path + (
                ("?" + request.url.query) if request.url.query else ""
            )
            qs = urlencode({"redirect_to": full}, quote_via=quote)
            return RedirectResponse(
                url=f"/login?{qs}",
                status_code=303,
            )

        return await call_next(request)
