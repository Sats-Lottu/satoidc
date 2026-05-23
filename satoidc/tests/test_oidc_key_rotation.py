import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

import satoidc.auth.oidc_signing_backends as signing_backends
from satoidc.auth.oauth2 import OpenIDCode
from satoidc.auth.oidc_keys import (
    activate_signing_key,
    create_signing_key,
    get_active_jwt_config,
    get_jwks,
    list_signing_keys,
    retire_expired_signing_keys,
    rotate_signing_key,
)
from satoidc.auth.oidc_signing_backends import (
    TransitClient,
    TransitSigningBackend,
    get_signing_backend,
)
from satoidc.models import OidcSigningKey, OidcSigningKeyAuditEvent


def _jwt_header(token: bytes | str) -> dict:
    if isinstance(token, bytes):
        token = token.decode()
    encoded_header = token.split(".", 1)[0]
    padding = "=" * (-len(encoded_header) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded_header + padding))


class Client:
    @staticmethod
    def get_client_id():
        return "client-1"


LATEST_TRANSIT_VERSION = 3
DEFAULT_TRANSIT_TIMEOUT = 5.0


async def test_jwks_bootstraps_persistent_active_key(db_session):
    jwks = get_jwks()
    key = jwks["keys"][0]

    stored_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == key["kid"])
    )

    assert stored_key is not None
    assert stored_key.status == "active"
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    for private_member in ("d", "p", "q", "dp", "dq", "qi"):
        assert private_member not in key


async def test_rotation_keeps_previous_key_publishable(db_session):
    original_kid = get_jwks()["keys"][0]["kid"]

    rotated = rotate_signing_key()
    jwks_kids = {key["kid"] for key in get_jwks()["keys"]}
    original_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == original_kid)
    )

    assert rotated.kid != original_kid
    assert jwks_kids == {original_kid, rotated.kid}
    assert original_key.status == "validating"
    assert original_key.retired_after is not None


async def test_activate_signing_key_allows_only_one_active_key(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    second_key = create_signing_key()

    activated = activate_signing_key(second_key.kid)
    active_keys = (
        await db_session.scalars(
            select(OidcSigningKey).where(OidcSigningKey.status == "active")
        )
    ).all()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )

    assert activated.kid == second_key.kid
    assert [key.kid for key in active_keys] == [second_key.kid]
    assert first_key.status == "validating"


async def test_activate_current_active_key_keeps_it_active(db_session):
    active_kid = get_jwks()["keys"][0]["kid"]

    activated = activate_signing_key(active_kid)
    active_keys = (
        await db_session.scalars(
            select(OidcSigningKey).where(OidcSigningKey.status == "active")
        )
    ).all()

    assert activated.kid == active_kid
    assert [key.kid for key in active_keys] == [active_kid]


async def test_activate_signing_key_rejects_unknown_or_retired_key(
    db_session,
):
    retired_key = create_signing_key(status="retired")

    with pytest.raises(
        ValueError, match="Unknown OIDC signing key: missing-kid"
    ):
        activate_signing_key("missing-kid")

    with pytest.raises(
        ValueError, match="Retired OIDC signing keys cannot be activated"
    ):
        activate_signing_key(retired_key.kid)


async def test_retire_expired_keys_removes_them_from_jwks(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    rotate_signing_key()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )
    first_key.retired_after = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    retired_count = retire_expired_signing_keys()
    jwks_kids = {key["kid"] for key in get_jwks()["keys"]}
    await db_session.refresh(first_key)

    assert retired_count == 1
    assert first_key.status == "retired"
    assert first_kid not in jwks_kids


async def test_retire_expired_signing_keys_ignores_unexpired_keys(db_session):
    first_kid = get_jwks()["keys"][0]["kid"]
    rotate_signing_key()
    first_key = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == first_kid)
    )

    retired_count = retire_expired_signing_keys()
    await db_session.refresh(first_key)

    assert retired_count == 0
    assert first_key.status == "validating"


async def test_active_jwt_config_and_key_listing_use_persisted_key(db_session):
    config = get_active_jwt_config()
    keys = list_signing_keys()

    assert config["kid"] == keys[0].kid
    assert config["alg"] == "RS256"
    assert config["iss"]
    assert config["exp"] > 0
    assert keys[0].status == "active"


def test_active_jwt_config_logs_sanitized_decrypt_failure(
    monkeypatch, caplog, assert_no_sensitive_log_values
):
    get_jwks()
    caplog.set_level(logging.ERROR, logger="satoidc.auth.oidc_keys")

    def fail_decrypt(encrypted_private_jwk):
        raise RuntimeError("private-jwk-secret")

    monkeypatch.setattr(
        "satoidc.auth.oidc_signing_backends._decrypt_private_jwk",
        fail_decrypt,
    )

    with pytest.raises(RuntimeError, match="private-jwk-secret"):
        get_active_jwt_config()

    assert any(
        record.event_name == "oidc.signing_config_failed"
        and record.component == "oidc_keys"
        and record.reason == "RuntimeError"
        for record in caplog.records
    )
    assert_no_sensitive_log_values("private-jwk-secret")


def test_transit_backend_fails_closed(monkeypatch, caplog):
    get_jwks()
    caplog.set_level(logging.ERROR, logger="satoidc.auth.oidc_keys")
    monkeypatch.setattr(
        "satoidc.auth.oidc_signing_backends.ENV.OIDC_SIGNING_BACKEND",
        "transit",
    )

    with pytest.raises(RuntimeError, match="OIDC_TRANSIT_ADDR"):
        get_active_jwt_config()

    assert any(
        record.event_name == "oidc.signing_config_failed"
        and record.component == "oidc_keys"
        and record.reason == "RuntimeError"
        for record in caplog.records
    )


class FakeTransitClient:
    def __init__(self):
        self.addr = "http://transit.example"
        self.token = "test-token"
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.version = 1

    def ensure_rsa_key(self, key_name):
        return {
            "type": "rsa-2048",
            "supports_signing": True,
            "keys": {str(self.version): 1},
        }

    def rotate_key(self, key_name):
        self.version += 1
        return self.ensure_rsa_key(key_name)

    def export_public_key(self, key_name, version):
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key.decode()

    def sign(self, key_name, version, signing_input, *, alg):
        hash_algorithm = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
            "PS256": hashes.SHA256(),
            "PS384": hashes.SHA384(),
            "PS512": hashes.SHA512(),
        }[alg]
        signature_padding = (
            padding.PKCS1v15()
            if alg.startswith("RS")
            else padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=hash_algorithm.digest_size,
            )
        )
        return self.private_key.sign(
            signing_input,
            signature_padding,
            hash_algorithm,
        )


def test_transit_backend_signs_jwt_without_private_material():
    fake_client = FakeTransitClient()
    backend = TransitSigningBackend(
        client=fake_client,
        key_name="satoidc-test",
    )
    key_row = backend.create_key_row(status="active")

    token = backend.encode_jwt(
        {"alg": "RS256", "kid": key_row.kid},
        {"iss": "issuer", "sub": "user-1"},
        key_row,
    )
    decoded = jwt.decode(
        token,
        RSAKey.import_key(json.loads(key_row.public_jwk)),
        ["RS256"],
    )

    assert not key_row.private_jwk_encrypted
    assert key_row.backend_reference == "transit:satoidc-test:1"
    assert decoded.header["kid"] == "satoidc-test-v1"
    assert decoded.claims["sub"] == "user-1"


def test_transit_backend_signs_ps384_jwt_without_private_material(
    monkeypatch,
):
    monkeypatch.setattr(
        "satoidc.auth.oidc_signing_backends.ENV.OAUTH2_JWT_ALG",
        "PS384",
    )
    fake_client = FakeTransitClient()
    backend = TransitSigningBackend(
        client=fake_client,
        key_name="satoidc-test",
    )
    key_row = backend.create_key_row(status="active")

    token = backend.encode_jwt(
        {"alg": "PS384", "kid": key_row.kid},
        {"iss": "issuer", "sub": "user-1"},
        key_row,
    )
    decoded = jwt.decode(
        token,
        RSAKey.import_key(json.loads(key_row.public_jwk)),
        ["PS384"],
    )

    assert key_row.alg == "PS384"
    assert decoded.header["alg"] == "PS384"
    assert decoded.claims["sub"] == "user-1"


def test_transit_backend_rotation_tracks_key_version():
    fake_client = FakeTransitClient()
    backend = TransitSigningBackend(
        client=fake_client,
        key_name="satoidc-test",
    )

    rotated = backend.create_key_row(
        status="validating",
        rotate_backend_key=True,
    )

    assert rotated.kid == "satoidc-test-v2"
    assert rotated.backend_reference == "transit:satoidc-test:2"


def test_transit_backend_jwt_config_exposes_public_metadata():
    fake_client = FakeTransitClient()
    backend = TransitSigningBackend(
        client=fake_client,
        key_name="satoidc-test",
    )
    key_row = backend.create_key_row(status="active")

    config = backend.jwt_config(key_row)

    assert config["key"] is None
    assert config["kid"] == key_row.kid
    assert config["alg"] == key_row.alg
    assert config["iss"]
    assert config["exp"] > 0


def test_transit_backend_jwt_config_requires_client_configuration():
    backend = TransitSigningBackend(
        client=TransitClient(addr="", token=""),
        key_name="satoidc-test",
    )
    key_row = OidcSigningKey(
        kid="kid",
        alg="RS256",
        kty="RSA",
        use="sig",
        status="active",
        public_jwk="{}",
        private_jwk_encrypted="",
        backend_reference="transit:satoidc-test:1",
    )

    with pytest.raises(RuntimeError, match="OIDC_TRANSIT_ADDR"):
        backend.jwt_config(key_row)


def test_transit_backend_rejects_invalid_reference():
    backend = TransitSigningBackend(
        client=FakeTransitClient(),
        key_name="satoidc-test",
    )
    key_row = OidcSigningKey(
        kid="bad",
        alg="RS256",
        kty="RSA",
        use="sig",
        status="active",
        public_jwk="{}",
        private_jwk_encrypted="",
        backend_reference="invalid-reference",
    )

    with pytest.raises(RuntimeError, match="Invalid Transit backend"):
        backend.encode_jwt({"alg": "RS256"}, {"sub": "user"}, key_row)


async def test_run_async_http_uses_thread_when_loop_is_running():
    async def coro():
        return "ok"

    assert signing_backends._run_async_http(coro) == "ok"


async def test_run_async_http_reraises_thread_errors():
    async def fail():
        raise RuntimeError("thread failure")

    with pytest.raises(RuntimeError, match="thread failure"):
        signing_backends._run_async_http(fail)


async def test_transit_client_request_async_handles_response_shapes(
    monkeypatch,
):
    calls = []

    class Response:
        def __init__(self, content=b"{}", payload=None):
            self.content = content
            self.payload = payload or {}

        def raise_for_status(self):
            assert self.content is not None

        def json(self):
            return self.payload

    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

        async def request(self, method, url, json=None, headers=None):
            calls.append((method, url, json, headers, self.timeout))
            if url.endswith("/empty"):
                return Response(content=b"")
            return Response(payload={"data": {"ok": True}})

    monkeypatch.setattr(signing_backends.httpx, "AsyncClient", FakeAsyncClient)
    client = TransitClient(
        addr="http://vault.example/",
        token="token",
        mount="/transit/",
        timeout_seconds=1.5,
    )

    assert await client.request_async("GET", "/metadata") == {
        "data": {"ok": True}
    }
    assert await client.request_async("GET", "empty") == {}
    assert calls[0] == (
        "GET",
        "http://vault.example/v1/transit/metadata",
        None,
        {"X-Vault-Token": "token"},
        1.5,
    )


async def test_transit_client_request_async_fails_closed(monkeypatch):
    class FakeAsyncClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

        async def request(self, method, url, json=None, headers=None):
            assert self.timeout == DEFAULT_TRANSIT_TIMEOUT
            if url.endswith("/status"):
                request = httpx.Request(method, url)
                response = httpx.Response(
                    500,
                    text="server error",
                    request=request,
                )
                raise httpx.HTTPStatusError(
                    "bad status",
                    request=request,
                    response=response,
                )
            raise httpx.ConnectError("network down")

    monkeypatch.setattr(signing_backends.httpx, "AsyncClient", FakeAsyncClient)
    client = TransitClient(addr="http://vault.example", token="token")

    with pytest.raises(RuntimeError, match="HTTP 500: server error"):
        await client.request_async("GET", "status")
    with pytest.raises(RuntimeError, match="network down"):
        await client.request_async("GET", "network")
    with pytest.raises(RuntimeError, match="OIDC_TRANSIT_ADDR"):
        await TransitClient(addr="", token="").request_async("GET", "status")


@pytest.mark.parametrize(
    ("alg", "expected"),
    [
        (
            "RS256",
            {
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            },
        ),
        (
            "RS384",
            {
                "hash_algorithm": "sha2-384",
                "signature_algorithm": "pkcs1v15",
            },
        ),
        (
            "RS512",
            {
                "hash_algorithm": "sha2-512",
                "signature_algorithm": "pkcs1v15",
            },
        ),
        (
            "PS256",
            {
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pss",
                "salt_length": "hash",
            },
        ),
        (
            "PS512",
            {
                "hash_algorithm": "sha2-512",
                "signature_algorithm": "pss",
                "salt_length": "hash",
            },
        ),
    ],
)
def test_transit_signing_parameters_map_supported_algorithms(alg, expected):
    assert signing_backends._transit_signing_parameters(alg) == expected


def test_transit_signing_parameters_reject_unknown_algorithm():
    with pytest.raises(RuntimeError, match="Unsupported Transit"):
        signing_backends._transit_signing_parameters("ES256")


def test_transit_helpers_decode_signatures_and_latest_versions():
    signature = signing_backends._decode_vault_signature(
        "vault:v1:c2lnbmF0dXJl"
    )

    assert signature == b"signature"
    assert (
        signing_backends._latest_version(
            {"keys": {"1": {}, "3": {}, "2": {}}}
        )
        == LATEST_TRANSIT_VERSION
    )
    with pytest.raises(RuntimeError, match="does not expose"):
        signing_backends._latest_version({"keys": {}})


def test_transit_client_key_management_uses_vault_contract():
    requests = []
    new_key_reads = 0

    class StubClient(TransitClient):
        def request(self, method, path, payload=None):
            nonlocal new_key_reads
            assert self.addr == "http://vault.example"
            requests.append((method, path, payload))
            if path == "keys/missing":
                raise RuntimeError("Transit request failed with HTTP 404: no")
            if path == "keys/explode":
                raise RuntimeError("boom")
            if path == "keys/new-key":
                new_key_reads += 1
                if new_key_reads == 1:
                    raise RuntimeError(
                        "Transit request failed with HTTP 404: no"
                    )
            if path == "keys/bad-key":
                return {"data": {"type": "ed25519", "supports_signing": True}}
            if path == "keys/no-sign":
                return {
                    "data": {
                        "type": "rsa-2048",
                        "supports_signing": False,
                    }
                }
            if path == "keys/empty-after-rotate":
                return {}
            if path.startswith("export/public-key/missing-public"):
                return {"data": {"keys": {}}}
            if path.startswith("export/public-key/ok-key"):
                return {"data": {"keys": {"1": "PUBLIC KEY"}}}
            return {
                "data": {
                    "type": "rsa-2048",
                    "supports_signing": True,
                    "keys": {"1": {}},
                }
            }

    client = StubClient(addr="http://vault.example", token="token")

    assert client.read_key("missing") is None
    with pytest.raises(RuntimeError, match="boom"):
        client.read_key("explode")
    assert client.ensure_rsa_key("new-key")["type"] == "rsa-2048"
    assert client.rotate_key("ok-key")["type"] == "rsa-2048"
    assert client.export_public_key("ok-key", 1)
    with pytest.raises(RuntimeError, match="type rsa-2048"):
        client.ensure_rsa_key("bad-key")
    with pytest.raises(RuntimeError, match="does not support signing"):
        client.ensure_rsa_key("no-sign")
    with pytest.raises(RuntimeError, match="rotation did not return"):
        client.rotate_key("empty-after-rotate")
    with pytest.raises(RuntimeError, match="did not include key"):
        client.export_public_key("missing-public", 1)
    assert ("POST", "keys/new-key", {"type": "rsa-2048"}) in requests


def test_transit_client_sign_builds_expected_payload():
    calls = []

    class StubClient(TransitClient):
        def request(self, method, path, payload=None):
            assert self.addr == "http://vault.example"
            calls.append((method, path, payload))
            return {"data": {"signature": "vault:v1:c2lnbmF0dXJl"}}

    client = StubClient(addr="http://vault.example", token="token")

    signature = client.sign(
        "satoidc-test",
        2,
        b"header.payload",
        alg="PS384",
    )

    assert signature == b"signature"
    assert calls == [
        (
            "POST",
            "sign/satoidc-test/sha2-384",
            {
                "input": "aGVhZGVyLnBheWxvYWQ=",
                "key_version": 2,
                "signature_algorithm": "pss",
                "salt_length": "hash",
            },
        )
    ]


def test_transit_client_sign_requires_signature_in_response():
    class StubClient(TransitClient):
        def request(self, method, path, payload=None):
            assert self.addr == "http://vault.example"
            return {"data": {}}

    client = StubClient(addr="http://vault.example", token="token")

    with pytest.raises(RuntimeError, match="did not include signature"):
        client.sign("satoidc-test", 1, b"payload", alg="RS256")


def test_get_signing_backend_rejects_unknown_backend(monkeypatch):
    monkeypatch.setattr(
        "satoidc.auth.oidc_signing_backends.ENV.OIDC_SIGNING_BACKEND",
        "unsupported",
    )

    with pytest.raises(RuntimeError, match="Unsupported OIDC signing backend"):
        get_signing_backend()


async def test_backend_switch_demotes_previous_active_key(
    monkeypatch, db_session
):
    database_key = get_jwks()["keys"][0]
    fake_client = FakeTransitClient()
    backend = TransitSigningBackend(
        client=fake_client,
        key_name="satoidc-test",
    )
    monkeypatch.setattr(
        "satoidc.auth.oidc_signing_backends.get_signing_backend",
        lambda: backend,
    )
    monkeypatch.setattr(
        "satoidc.auth.oidc_keys.get_signing_backend",
        lambda: backend,
    )

    transit_key = get_jwks()["keys"][0]
    database_row = await db_session.scalar(
        select(OidcSigningKey).where(OidcSigningKey.kid == database_key["kid"])
    )

    assert transit_key["kid"] == "satoidc-test-v1"
    assert database_row.status == "validating"


async def test_id_token_uses_active_kid_and_audits_signature(
    db_session, make_user
):
    user = await make_user()
    active_kid = get_jwks()["keys"][0]["kid"]
    request = SimpleNamespace(
        client=Client(),
        authorization_code=None,
        user=user,
    )

    id_token = OpenIDCode(require_nonce=True).encode_id_token(
        {"scope": "openid profile", "access_token": "access-token"},
        request,
    )
    header = _jwt_header(id_token)
    audit_event = await db_session.scalar(
        select(OidcSigningKeyAuditEvent).where(
            OidcSigningKeyAuditEvent.event == "token.signed",
            OidcSigningKeyAuditEvent.kid == active_kid,
        )
    )

    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == active_kid
    assert audit_event is not None
