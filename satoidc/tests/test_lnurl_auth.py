import ecdsa
from sqlalchemy import select

from satoidc.auth.lnurl import url_encode, verify
from satoidc.auth.lnurl_schemas import LnurlAuthCallbackIn
from satoidc.models import LnurlAuthChallenge
from satoidc.routes.lnurl_auth import lnurl_auth_callback


def _wallet_signature(k1: str) -> tuple[str, str]:
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    signature = signing_key.sign_digest(
        bytes.fromhex(k1),
        sigencode=ecdsa.util.sigencode_der,
    )
    return verifying_key.to_string("compressed").hex(), signature.hex()


def test_lnurl_encoding_produces_bech32_lnurl():
    encoded = url_encode(
        "http://localhost:8000/auth/lnurl/callback?tag=login&k1=abc"
    )

    assert encoded.startswith("LNURL")


def test_lnurl_signature_verification_uses_real_secp256k1_key():
    k1 = "a" * 64
    key, signature = _wallet_signature(k1)

    assert verify(k1, key, signature)
    assert not verify("b" * 64, key, signature)


async def test_lnurl_login_callback_links_existing_user(
    db_session, make_user
):
    k1 = "1" * 64
    key, signature = _wallet_signature(k1)
    user = await make_user(lnurl_pubkey=key)
    challenge = LnurlAuthChallenge(k1=k1, action="login")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="login",
        ),
        db_session,
    )

    stored_challenge = await db_session.scalar(
        select(LnurlAuthChallenge).where(LnurlAuthChallenge.k1 == k1)
    )
    assert response == {"status": "OK"}
    assert stored_challenge.verified is True
    assert stored_challenge.user_id == user.id


async def test_lnurl_callback_rejects_unknown_challenge(db_session):
    key, signature = _wallet_signature("2" * 64)

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1="2" * 64,
            key=key,
            sig=signature,
            action="login",
        ),
        db_session,
    )

    assert response == {
        "status": "ERROR",
        "reason": "Invalid or expired k1",
    }
