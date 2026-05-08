from typing import Annotated, Optional

from fastapi import Form
from pydantic import BaseModel


class RegisterSchema(BaseModel):
    login: str
    email: str
    nickname: Optional[str] = None
    password: str
    confirm_password: str
    redirect_to: Optional[str] = "/profile"
    terms_accepted: bool = False


RegisterForm = Annotated[RegisterSchema, Form()]
