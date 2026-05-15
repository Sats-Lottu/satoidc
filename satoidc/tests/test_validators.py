from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_nickname,
    is_valid_password,
    validate_registration_form,
)


def test_registration_validators_accept_realistic_user_input():
    assert is_valid_login("satoshi1")
    assert is_valid_email("satoshi@example.com")
    assert is_valid_nickname("Satoshi_01")
    assert is_valid_password("StrongPass1!")

    errors = validate_registration_form(
        login="satoshi1",
        nickname="Satoshi_01",
        password="StrongPass1!",
        email="satoshi@example.com",
    )

    assert errors == {}


def test_registration_validators_reject_invalid_input():
    errors = validate_registration_form(
        login="Sat",
        nickname="-bad-",
        password="weak",
        email="not-an-email",
    )

    assert set(errors) == {"login", "nickname", "password", "email"}


def test_individual_validators_reject_boundary_and_format_errors():
    assert not is_valid_login("Satoshi1")
    assert not is_valid_login("abc12")
    assert not is_valid_login("a" * 31)

    assert is_valid_nickname("")
    assert not is_valid_nickname(".satoshi")
    assert not is_valid_nickname("satoshi-")
    assert not is_valid_nickname("a" * 81)

    assert not is_valid_password("NoSpecial123")
    assert not is_valid_password("nospecial1!")
    assert not is_valid_password("NOLOWER1!")
    assert not is_valid_password("NoDigit!!")

    assert not is_valid_email("missing-at.example")
