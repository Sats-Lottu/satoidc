from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from cryptography.fernet import Fernet
from joserfc import jwk, jwt

from satoidc.models import OidcSigningKey
from satoidc.settings import ENV


class OidcSigningBackend(Protocol):
    backend_reference: str

    def create_key_row(
        self,
        *,
        status: str,
        rotate_backend_key: bool = False,
    ) -> OidcSigningKey:
        """Create a persisted key metadata row for this backend."""

    def jwt_config(self, key_row: OidcSigningKey) -> dict[str, Any]:  # noqa: PLR6301
        """Return the Authlib JWT configuration for the selected key row."""

    def encode_jwt(
        self,
        header: dict[str, Any],
        claims: dict[str, Any],
        key_row: OidcSigningKey,
    ) -> str:
        """Encode and sign an ID Token for this backend."""


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

    def create_key_row(
        self,
        *,
        status: str,
        rotate_backend_key: bool = False,
    ) -> OidcSigningKey:
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

    def encode_jwt(
        self,
        header: dict[str, Any],
        claims: dict[str, Any],
        key_row: OidcSigningKey,
    ) -> str:
        jwt_config = self.jwt_config(key_row)
        return jwt.encode(header, claims, jwt_config["key"], [key_row.alg])


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_b64url(payload: dict[str, Any]) -> str:
    return _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )


def _standard_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_vault_signature(signature: str) -> bytes:
    encoded_signature = signature.rsplit(":", 1)[-1]
    return base64.b64decode(encoded_signature)


def _run_async_http(coro_factory: Callable[[], Coroutine[Any, Any, Any]]):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())

    result: dict[str, Any] = {}

    def runner():
        try:
            result["value"] = asyncio.run(coro_factory())
        except Exception as exc:  # pragma: no cover - re-raised below
            result["error"] = exc

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


@dataclass(frozen=True)
class TransitClient:
    addr: str
    token: str
    mount: str = "transit"
    timeout_seconds: float = 5.0

    def _url(self, path: str) -> str:
        mount = self.mount.strip("/")
        return f"{self.addr.rstrip('/')}/v1/{mount}/{path.lstrip('/')}"

    async def request_async(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.addr or not self.token:
            raise RuntimeError(
                "OIDC Transit signing requires OIDC_TRANSIT_ADDR and "
                "OIDC_TRANSIT_TOKEN."
            )
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds
            ) as client:
                response = await client.request(
                    method,
                    self._url(path),
                    json=payload,
                    headers={"X-Vault-Token": self.token},
                )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                "Transit request failed with HTTP "
                f"{exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Transit request failed: {exc}") from exc
        if not response.content:
            return {}
        return response.json()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return _run_async_http(
            lambda: self.request_async(method, path, payload)
        )

    def read_key(self, key_name: str) -> dict[str, Any] | None:
        try:
            response = self.request("GET", f"keys/{key_name}")
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        return response.get("data", {})

    def ensure_rsa_key(self, key_name: str) -> dict[str, Any]:
        key = self.read_key(key_name)
        if key is None:
            self.request("POST", f"keys/{key_name}", {"type": "rsa-2048"})
            key = self.read_key(key_name)
        if not key or key.get("type") != "rsa-2048":
            raise RuntimeError("Transit key must exist with type rsa-2048.")
        if not key.get("supports_signing", False):
            raise RuntimeError("Transit key does not support signing.")
        return key

    def rotate_key(self, key_name: str) -> dict[str, Any]:
        self.request("POST", f"keys/{key_name}/rotate")
        key = self.read_key(key_name)
        if not key:
            raise RuntimeError("Transit key rotation did not return metadata.")
        return key

    def export_public_key(self, key_name: str, version: int) -> str:
        response = self.request(
            "GET", f"export/public-key/{key_name}/{version}"
        )
        keys = response.get("data", {}).get("keys", {})
        public_key = keys.get(str(version))
        if not public_key:
            raise RuntimeError(
                "Transit public key export did not include key."
            )
        return public_key

    def sign(self, key_name: str, version: int, signing_input: bytes) -> bytes:
        response = self.request(
            "POST",
            f"sign/{key_name}/sha2-256",
            {
                "input": _standard_b64(signing_input),
                "key_version": version,
                "signature_algorithm": "pkcs1v15",
            },
        )
        signature = response.get("data", {}).get("signature")
        if not signature:
            raise RuntimeError(
                "Transit sign response did not include signature."
            )
        return _decode_vault_signature(signature)


def _latest_version(key_metadata: dict[str, Any]) -> int:
    versions = [int(version) for version in key_metadata.get("keys", {})]
    if not versions:
        raise RuntimeError("Transit key does not expose any versions.")
    return max(versions)


@dataclass(frozen=True)
class TransitSigningBackend:
    client: TransitClient
    key_name: str
    backend_reference: str = "transit"

    def create_key_row(
        self,
        *,
        status: str,
        rotate_backend_key: bool = False,
    ) -> OidcSigningKey:
        key_metadata = (
            self.client.rotate_key(self.key_name)
            if rotate_backend_key
            else self.client.ensure_rsa_key(self.key_name)
        )
        version = _latest_version(key_metadata)
        public_key_pem = self.client.export_public_key(self.key_name, version)
        public_jwk = jwk.import_key(public_key_pem).as_dict(private=False)
        public_jwk["alg"] = ENV.OAUTH2_JWT_ALG
        public_jwk["use"] = "sig"
        kid = f"{self.key_name}-v{version}"
        public_jwk["kid"] = kid
        return OidcSigningKey(
            kid=kid,
            alg=ENV.OAUTH2_JWT_ALG,
            kty="RSA",
            use="sig",
            status=status,
            public_jwk=json.dumps(public_jwk, sort_keys=True),
            private_jwk_encrypted="",
            backend_reference=f"transit:{self.key_name}:{version}",
        )

    def jwt_config(self, key_row: OidcSigningKey) -> dict[str, Any]:  # noqa: PLR6301
        if not self.client.addr or not self.client.token:
            raise RuntimeError(
                "OIDC Transit signing requires OIDC_TRANSIT_ADDR and "
                "OIDC_TRANSIT_TOKEN."
            )
        return {
            "key": None,
            "kid": key_row.kid,
            "alg": key_row.alg,
            "iss": ENV.OAUTH2_JWT_ISS,
            "exp": ENV.OAUTH2_TOKEN_EXPIRES_IN,
        }

    def encode_jwt(
        self,
        header: dict[str, Any],
        claims: dict[str, Any],
        key_row: OidcSigningKey,
    ) -> str:
        reference = key_row.backend_reference or ""
        try:
            _, key_name, version_text = reference.split(":", 2)
            version = int(version_text)
        except ValueError as exc:
            raise RuntimeError("Invalid Transit backend reference.") from exc
        header_segment = _json_b64url({"typ": "JWT", **header})
        payload_segment = _json_b64url(claims)
        signing_input = f"{header_segment}.{payload_segment}".encode()
        signature = self.client.sign(key_name, version, signing_input)
        return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def get_signing_backend() -> OidcSigningBackend:
    if ENV.OIDC_SIGNING_BACKEND == "database":
        return DatabaseSigningBackend()
    if ENV.OIDC_SIGNING_BACKEND == "transit":
        return TransitSigningBackend(
            client=TransitClient(
                addr=ENV.OIDC_TRANSIT_ADDR,
                token=ENV.OIDC_TRANSIT_TOKEN,
                mount=ENV.OIDC_TRANSIT_MOUNT,
            ),
            key_name=ENV.OIDC_TRANSIT_KEY_NAME,
        )
    raise RuntimeError(
        f"Unsupported OIDC signing backend: {ENV.OIDC_SIGNING_BACKEND}"
    )
