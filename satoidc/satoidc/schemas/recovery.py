from typing import Annotated

from fastapi import Form
from pydantic import BaseModel


class ForgotPasswordSchema(BaseModel):
    email: str


class ResetPasswordSchema(BaseModel):
    token: str
    password: str
    confirm_password: str


ForgotPasswordForm = Annotated[ForgotPasswordSchema, Form()]
ResetPasswordForm = Annotated[ResetPasswordSchema, Form()]
