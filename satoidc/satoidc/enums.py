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


class ResponseTypeEnum(StrEnum):
    CODE = "code"
    # Future implicit/hybrid flow values belong behind a dedicated spec.
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
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
