from urllib.parse import urlparse

CONTROL_CHARACTER_LIMIT = 32
DELETE_CHARACTER_CODE = 127


def safe_redirect(redirect_to: str | None) -> str:
    """Accept only local absolute-path redirects."""
    if not redirect_to:
        return "/"
    if redirect_to != redirect_to.strip():
        return "/"
    if any(
        ord(char) < CONTROL_CHARACTER_LIMIT
        or ord(char) == DELETE_CHARACTER_CODE
        for char in redirect_to
    ):
        return "/"
    parsed = urlparse(redirect_to)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not redirect_to.startswith("/"):
        return "/"
    return redirect_to
