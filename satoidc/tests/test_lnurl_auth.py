import logging
from uuid import uuid4

import ecdsa
from sqlalchemy import select

from satoidc.auth.lnurl import url_encode, verify
from satoidc.models import LnurlAuthChallenge, User
from satoidc.routes.lnurl_auth import lnurl_auth_callback
from satoidc.schemas.lnurl import LnurlAuthCallbackIn


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
    assert stored_challenge.consumed is True
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


async def test_lnurl_callback_rejects_action_mismatch(db_session):
    k1 = "4" * 64
    key, signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(k1=k1, action="login")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="register",
        ),
        db_session,
    )

    assert response == {"status": "ERROR", "reason": "Action mismatch"}


async def test_lnurl_callback_rejects_bad_signature(
    db_session, caplog, assert_no_sensitive_log_values
):
    caplog.set_level(logging.INFO, logger="satoidc.routes.lnurl_auth")
    k1 = "5" * 64
    key, _signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(k1=k1, action="login")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig="0" * 16,
            action="login",
        ),
        db_session,
    )

    assert response == {"status": "ERROR", "reason": "Bad Signature Error"}
    assert any(
        record.event_name == "lnurl.callback_failed"
        and record.component == "lnurl_auth"
        and record.reason == "bad_signature"
        for record in caplog.records
    )
    assert_no_sensitive_log_values("0000000000000000")

    stored_challenge = await db_session.scalar(
        select(LnurlAuthChallenge).where(LnurlAuthChallenge.k1 == k1)
    )
    assert stored_challenge.consumed is True


async def test_lnurl_register_callback_creates_wallet_user(db_session):
    k1 = "6" * 64
    key, signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(k1=k1, action="register")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="register",
        ),
        db_session,
    )

    user = await db_session.scalar(
        select(User).where(User.lnurl_pubkey == key)
    )

    assert response == {"status": "OK"}
    assert user.lnurl_pubkey == key
    assert user.nickname == "satoshi"


async def test_lnurl_login_rejects_unlinked_wallet(db_session):
    k1 = "7" * 64
    key, signature = _wallet_signature(k1)
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

    assert response == {
        "status": "ERROR",
        "reason": "User not found for this linkingKey",
    }


async def test_lnurl_link_callback_updates_existing_user(
    db_session, make_user
):
    k1 = "8" * 64
    key, signature = _wallet_signature(k1)
    user = await make_user(lnurl_pubkey=None)
    challenge = LnurlAuthChallenge(k1=k1, action="link", user_id=user.id)
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="link",
        ),
        db_session,
    )

    await db_session.refresh(user)
    assert response == {"status": "OK"}
    assert user.lnurl_pubkey == key


async def test_lnurl_link_callback_rejects_wallet_owned_by_another_user(
    db_session, make_user
):
    k1 = "b" * 64
    key, signature = _wallet_signature(k1)
    owner = await make_user(
        login="owner",
        email="owner@example.com",
        lnurl_pubkey=key,
    )
    requester = await make_user(
        login="requester",
        email="requester@example.com",
        lnurl_pubkey=None,
    )
    challenge = LnurlAuthChallenge(
        k1=k1, action="link", user_id=requester.id
    )
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="link",
        ),
        db_session,
    )

    await db_session.refresh(owner)
    await db_session.refresh(requester)
    assert response == {
        "status": "ERROR",
        "reason": "Wallet already linked to another account",
    }
    assert owner.lnurl_pubkey == key
    assert requester.lnurl_pubkey is None


async def test_lnurl_link_callback_requires_challenge_user(db_session):
    k1 = "c" * 64
    key, signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(k1=k1, action="link")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="link",
        ),
        db_session,
    )

    assert response == {
        "status": "ERROR",
        "reason": "Missing linked account",
    }


async def test_lnurl_link_callback_rejects_missing_linked_user(db_session):
    k1 = "d" * 64
    key, signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(
        k1=k1, action="link", user_id=uuid4()
    )
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        LnurlAuthCallbackIn(
            k1=k1,
            key=key,
            sig=signature,
            action="link",
        ),
        db_session,
    )

    assert response == {
        "status": "ERROR",
        "reason": "Linked account not found",
    }


async def test_lnurl_callback_rejects_missing_action(db_session):
    k1 = "a" * 64
    key, signature = _wallet_signature(k1)
    challenge = LnurlAuthChallenge(k1=k1, action="weird")
    db_session.add(challenge)
    await db_session.commit()

    response = await lnurl_auth_callback(
        type(
            "UnknownActionQuery",
            (),
            {
                "k1": k1,
                "key": key,
                "sig": signature,
                "action": "weird",
            },
        )(),
        db_session,
    )

    assert response == {"status": "ERROR", "reason": "Unknown action"}
