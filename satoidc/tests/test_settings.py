import pytest

from satoidc.settings import PLACEHOLDER_SECRET, Settings


def test_session_cookie_https_only_defaults_to_environment():
    dev_settings = Settings(_env_file=None)
    prod_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
        OAUTH2_JWT_SECRET_KEY="jwt-secret",
    )

    assert dev_settings.session_cookie_https_only is False
    assert prod_settings.session_cookie_https_only is True


def test_session_cookie_https_only_can_be_enabled_before_production():
    settings = Settings(_env_file=None, SESSION_COOKIE_HTTPS_ONLY=True)

    assert settings.session_cookie_https_only is True


def test_production_rejects_placeholder_secrets():
    with pytest.raises(ValueError, match="SESSION_MIDDLEWARE_SECRET_KEY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SESSION_MIDDLEWARE_SECRET_KEY=PLACEHOLDER_SECRET,
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
        )


def test_production_rejects_insecure_session_cookie_override():
    with pytest.raises(ValueError, match="SESSION_COOKIE_HTTPS_ONLY"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SESSION_MIDDLEWARE_SECRET_KEY="session-secret",
            OAUTH2_JWT_SECRET_KEY="jwt-secret",
            SESSION_COOKIE_HTTPS_ONLY=False,
        )
