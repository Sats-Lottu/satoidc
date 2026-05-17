import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from satoidc.utils import safe_redirect
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_nickname,
    is_valid_password,
)

pytestmark = pytest.mark.property


@settings(max_examples=80)
@given(st.text(max_size=128))
def test_safe_redirect_never_returns_external_targets(value: str) -> None:
    result = safe_redirect(value)

    assert result.startswith("/")
    assert not result.startswith("//")


@settings(max_examples=80)
@given(st.text(max_size=128))
def test_safe_redirect_rejects_control_characters(value: str) -> None:
    tainted = f"/profile{value}\n"

    assert safe_redirect(tainted) == "/"


@settings(max_examples=80)
@given(st.text(max_size=160))
def test_validators_return_booleans_for_arbitrary_text(value: str) -> None:
    assert isinstance(is_valid_login(value), bool)
    assert isinstance(is_valid_nickname(value), bool)
    assert isinstance(is_valid_password(value), bool)
    assert isinstance(is_valid_email(value), bool)
