import pytest

pytestmark = pytest.mark.api_security
SEE_OTHER = 303


def test_public_route_lookalikes_require_authentication(app_client) -> None:
    response = app_client.get("/oauth-settings", follow_redirects=False)

    assert response.status_code == SEE_OTHER
    assert response.headers["location"].startswith(
        "/login?redirect_to=%2Foauth-settings"
    )


def test_public_api_route_lookalikes_redirect_to_login(app_client) -> None:
    response = app_client.get("/api-admin", follow_redirects=False)

    assert response.status_code == SEE_OTHER
    assert response.headers["location"].startswith(
        "/login?redirect_to=%2Fapi-admin"
    )
