from enum import StrEnum, auto


class PermissionsEnum(StrEnum):
    ROOT = auto()
    ADMIN = auto()
    DEVELOPER = auto()
    SUPPORT = auto()


class PermissionRequestStatusEnum(StrEnum):
    PENDING = auto()
    APPROVED = auto()
    DENIED = auto()
    CANCELLED = auto()
    SUPERSEDED = auto()


class PKCEMethodEnum(StrEnum):
    PLAIN = "plain"
    S256 = "S256"


class GrantTypeEnum(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"  # opcional


class ResponseTypeEnum(StrEnum):
    CODE = "code"
    # Se no futuro quiser implicit/hybrid (OIDC), adicione:
    # ID_TOKEN = "id_token"
    # TOKEN = "token"
    # CODE_ID_TOKEN = "code id_token"
    # CODE_TOKEN = "code token"
    # CODE_ID_TOKEN_TOKEN = "code id_token token"


class TokenEndpointAuthMethodEnum(StrEnum):
    NONE = "none"  # public client (PKCE)
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    # Future options:
    # PRIVATE_KEY_JWT = "private_key_jwt"
    # TLS_CLIENT_AUTH = "tls_client_auth"


class JwkAlgEnum(StrEnum):
    # Prefer RS256 first for broad compatibility, then EdDSA.
    RS256 = "RS256"
    PS256 = "PS256"
    ES256 = "ES256"
    EDDSA = "EdDSA"
