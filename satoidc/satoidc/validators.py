import re

from pydantic import EmailStr, TypeAdapter, ValidationError

LOGIN_RE = re.compile(r"^[a-z0-9]{6,30}$")
NICKNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{1,78}[a-z0-9])?$",
    re.IGNORECASE,
)
PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,128}$"
)
email_adapter = TypeAdapter(EmailStr)


def is_valid_login(v: str) -> bool:
    return bool(LOGIN_RE.fullmatch(v))


def is_valid_nickname(v: str) -> bool:
    return bool(NICKNAME_RE.fullmatch(v)) if len(v) > 0 else True


def is_valid_password(v: str) -> bool:
    return bool(PASSWORD_RE.fullmatch(v))


def is_valid_email(v: str) -> bool:
    try:
        email_adapter.validate_python(v)
        return True
    except ValidationError:
        return False


def validate_registration_form(
    login: str, nickname: str, password: str, email: str
) -> dict:
    errors = {}
    if not is_valid_login(login):
        errors["login"] = "Login must be 6-30 lowercase letters and digits."
    if not is_valid_nickname(nickname):
        errors["nickname"] = (
            "Nickname must have a maximum of 80 characters, start/end with"
            " letter/digit, and can include ._-"
        )
    if not is_valid_password(password):
        errors["password"] = (
            "Password must be 8-128 chars, with upper/lowercase, digit, and"
            " special char."
        )
    if not is_valid_email(email):
        errors["email"] = "Invalid email address."
    return errors
