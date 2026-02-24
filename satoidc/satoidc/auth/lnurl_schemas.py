from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

LnurlAction = Optional[Literal["register", "login", "link", "auth"]]


class LnurlAuthCallbackIn(BaseModel):
    """
    Query params do callback LNURL-auth:
      GET /auth/lnurl/callback?k1=<hex32>&sig=<hexsig>&key=<hexpubkey>

    - k1: 32 bytes (64 hex chars)
    - key: pubkey comprimida secp256k1 (33 bytes = 66 hex chars; prefixo 02/03)
    - sig: assinatura em hex, pode ser:
        * compact/raw 64 bytes (128 hex chars), ou
        * DER (tamanho variável, normalmente 140~144 hex chars,
          mas pode variar)
    """

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
