from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.fernet import Fernet
from joserfc import jwk

from satoidc.models import OidcSigningKey
from satoidc.settings import ENV


class OidcSigningBackend(Protocol):
    backend_reference: str

    def create_key_row(self, *, status: str) -> OidcSigningKey:
        """Create a persisted key metadata row for this backend."""

    def jwt_config(self, key_row: OidcSigningKey) -> dict[str, Any]:  # noqa: PLR6301
        """Return the Authlib JWT configuration for the selected key row."""


def _fernet() -> Fernet:
    digest = hashlib.sha256(ENV.OAUTH2_JWT_SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt_private_jwk(private_jwk: dict[str, Any]) -> str:
    payload = json.dumps(private_jwk, sort_keys=True).encode()
    return _fernet().encrypt(payload).decode()


def _decrypt_private_jwk(encrypted_private_jwk: str) -> dict[str, Any]:
    payload = _fernet().decrypt(encrypted_private_jwk.encode())
    return json.loads(payload)


@dataclass(frozen=True)
class DatabaseSigningBackend:
    backend_reference: str = "database"

    def create_key_row(self, *, status: str) -> OidcSigningKey:
        key = jwk.generate_key("RSA", 2048, private=True, auto_kid=True)
        private_jwk = key.as_dict(private=True)
        public_jwk = key.as_dict(private=False)
        public_jwk["alg"] = ENV.OAUTH2_JWT_ALG
        public_jwk["use"] = "sig"
        kid = public_jwk["kid"]
        return OidcSigningKey(
            kid=kid,
            alg=ENV.OAUTH2_JWT_ALG,
            kty="RSA",
            use="sig",
            status=status,
            public_jwk=json.dumps(public_jwk, sort_keys=True),
            private_jwk_encrypted=_encrypt_private_jwk(private_jwk),
            backend_reference=self.backend_reference,
        )

    def jwt_config(self, key_row: OidcSigningKey) -> dict[str, Any]:  # noqa: PLR6301
        private_jwk = _decrypt_private_jwk(key_row.private_jwk_encrypted)
        return {
            "key": jwk.import_key(private_jwk),
            "kid": key_row.kid,
            "alg": key_row.alg,
            "iss": ENV.OAUTH2_JWT_ISS,
            "exp": ENV.OAUTH2_TOKEN_EXPIRES_IN,
        }


def get_signing_backend() -> OidcSigningBackend:
    if ENV.OIDC_SIGNING_BACKEND == "database":
        return DatabaseSigningBackend()
    if ENV.OIDC_SIGNING_BACKEND == "transit":
        raise RuntimeError(
            "OIDC_SIGNING_BACKEND=transit is configured, but the Transit "
            "backend client is not available yet."
        )
    raise RuntimeError(
        f"Unsupported OIDC signing backend: {ENV.OIDC_SIGNING_BACKEND}"
    )
