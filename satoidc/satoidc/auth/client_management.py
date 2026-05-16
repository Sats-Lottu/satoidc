import logging
import time
from secrets import token_urlsafe

from satoidc.enums import TokenEndpointAuthMethodEnum
from satoidc.models import OAuth2Client

CLIENT_DISABLED_AT = "disabled_at"
CLIENT_UPDATED_AT = "updated_at"
CLIENT_SECRET_ROTATED_AT = "client_secret_rotated_at"

log = logging.getLogger(__name__)


class ClientMetadataValidationError(ValueError):
    def __init__(self, messages: list[str]):
        self.messages = messages
        super().__init__("; ".join(messages))


def is_client_disabled(client: OAuth2Client) -> bool:
    metadata = client.client_metadata or {}
    return bool(metadata.get(CLIENT_DISABLED_AT))


def set_client_disabled(
    client: OAuth2Client, *, disabled: bool, now: int | None = None
) -> dict:
    timestamp = now or int(time.time())
    metadata = dict(client.client_metadata or {})
    if disabled:
        metadata[CLIENT_DISABLED_AT] = timestamp
    else:
        metadata.pop(CLIENT_DISABLED_AT, None)
    metadata[CLIENT_UPDATED_AT] = timestamp
    client.set_client_metadata(metadata)
    return metadata


def rotate_client_secret(
    client: OAuth2Client, *, now: int | None = None
) -> str:
    timestamp = now or int(time.time())
    metadata = dict(client.client_metadata or {})
    if metadata.get("token_endpoint_auth_method") == (
        TokenEndpointAuthMethodEnum.NONE.value
    ):
        log.info(
            "Client secret rotation rejected",
            extra={
                "event_name": "client.secret_rotation_failed",
                "component": "client_management",
                "outcome": "rejected",
                "reason": "public_client",
            },
        )
        raise ClientMetadataValidationError(
            ["Public clients do not have a secret to rotate."]
        )
    secret = token_urlsafe(64)
    client.client_secret = secret
    metadata[CLIENT_SECRET_ROTATED_AT] = timestamp
    metadata[CLIENT_UPDATED_AT] = timestamp
    client.set_client_metadata(metadata)
    return secret
