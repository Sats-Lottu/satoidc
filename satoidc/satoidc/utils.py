
from typing import Optional
from urllib.parse import urlparse


# ==========================================================
# Helpers (domínio / serviço)
# ==========================================================
def safe_redirect(redirect_to: Optional[str]) -> str:
    """Aceita apenas redirecionamento relativo (evita open-redirect)."""
    if not redirect_to:
        return "/"
    parsed = urlparse(redirect_to)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not redirect_to.startswith("/"):
        return "/"
    return redirect_to
