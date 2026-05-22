from typing import Annotated

from fastapi import Form
from pydantic import BaseModel


class CreateOAuthClientCommand(BaseModel):
    client_name: str = ""
    client_uri: str = ""
    redirect_uri: str = ""
    client_type: str = "confidential_web"
    token_endpoint_auth_method: str = "client_secret_basic"
    profile_scope: bool = True
    email_scope: bool = True
    refresh_token_enabled: bool = False


CreateOAuthClientCommandForm = Annotated[CreateOAuthClientCommand, Form()]
