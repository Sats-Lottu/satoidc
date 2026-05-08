from typing import Annotated, Optional

from fastapi import Form
from pydantic import BaseModel


class LoginSchema(BaseModel):
    identifier: str
    password: str
    redirect_to: Optional[str] = None
    login_nonce: Optional[str] = None


LoginForm = Annotated[LoginSchema, Form()]
