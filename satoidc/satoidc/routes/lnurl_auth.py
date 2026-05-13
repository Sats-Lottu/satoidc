from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.lnurl import lnurl_auth_events, verify
from satoidc.models import LnurlAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.schemas.lnurl import LnurlAuthCallbackIn
from satoidc.settings import ENV

router = APIRouter(prefix="/auth", tags=["LNURL Auth"])

Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/lnurl/callback", status_code=HTTPStatus.OK)
async def lnurl_auth_callback(  # noqa: PLR0911, PLR0912
    query: Annotated[LnurlAuthCallbackIn, Depends()], session: Session
):
    response = {"status": "ERROR", "reason": "Unknown error"}
    # 1) k1 must be expected, unused, not expired, and match its action.
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=ENV.LNURL_K1_TTL_SECONDS
    )
    challenge = await session.scalar(
        update(LnurlAuthChallenge)
        .where(
            LnurlAuthChallenge.k1 == query.k1,
            LnurlAuthChallenge.consumed.is_(False),
            LnurlAuthChallenge.created_at >= cutoff,
        )
        .values(consumed=True)
        .returning(LnurlAuthChallenge)
        .execution_options(synchronize_session=False)
    )
    if not challenge:
        return {"status": "ERROR", "reason": "Invalid or expired k1"}
    await session.refresh(challenge)
    if challenge.action != query.action:
        return {"status": "ERROR", "reason": "Action mismatch"}

    # 2) Verify the signature: wallet signs k1 with linkingPrivKey.
    if not verify(query.k1, query.key, query.sig):
        return {"status": "ERROR", "reason": "Bad Signature Error"}

    # 3) Resolve or create a user by linkingKey.
    db_user = await session.scalar(
        select(User).where(User.lnurl_pubkey == query.key)
    )
    match query.action:
        case "register":
            if not db_user:
                db_user = User(
                    password_hash=None,
                    email=None,
                    nickname=None,
                    lnurl_pubkey=query.key,
                    login=None,
                )
                session.add(db_user)
            challenge.user = db_user
            session.add(challenge)
            await session.commit()
            response = {"status": "OK"}

        case "login":
            if not db_user:
                return {
                    "status": "ERROR",
                    "reason": "User not found for this linkingKey",
                }
            challenge.user_id = db_user.id
            session.add(challenge)
            await session.commit()
            response = {"status": "OK"}
        case "link":
            # Link this linkingKey to an already authenticated account.
            if not challenge.user_id:
                return {
                    "status": "ERROR",
                    "reason": "Missing linked account",
                }
            if db_user and db_user.id != challenge.user_id:
                return {
                    "status": "ERROR",
                    "reason": "Wallet already linked to another account",
                }
            user = await session.scalar(
                select(User).where(User.id == challenge.user_id)
            )
            if not user:
                return {
                    "status": "ERROR",
                    "reason": "Linked account not found",
                }
            user.lnurl_pubkey = query.key
            session.add(user)
            await session.commit()
            response = {"status": "OK"}
        case "auth":
            # Authorize a stateless action without login.
            response = {"status": "OK"}
        case _:
            response = {"status": "ERROR", "reason": "Unknown action"}
    await lnurl_auth_events.call(
        {"k1": challenge.k1, "user_id": challenge.user_id}
    )
    return response
