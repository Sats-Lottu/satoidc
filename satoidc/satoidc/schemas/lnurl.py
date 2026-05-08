from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

LnurlAction = Optional[Literal["register", "login", "link", "auth"]]


class LnurlAuthCallbackIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    k1: str = Field(min_length=64, max_length=64, description="32 bytes hex")
    sig: str = Field(
        min_length=16,
        max_length=512,
        description="hex signature (DER or 64-byte compact)",
    )
    key: str = Field(
        min_length=66,
        max_length=66,
        description="compressed pubkey hex (33 bytes)",
    )
    action: LnurlAction
