from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.lnurl import url_encode, verify
from satoidc.auth.lnurl_schemas import LnurlAction, LnurlAuthCallbackIn
from satoidc.models import LnurlAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.settings import ENV

router = APIRouter(prefix="/auth", tags=["LNURL Auth"])

Session = Annotated[AsyncSession, Depends(get_session)]


@router.post(
    "/lnurl",
    status_code=HTTPStatus.CREATED,
)
async def get_lnurl(
    request: Request, session: Session, action: LnurlAction = "login"
):
    # Cria um desafio no banco para validar depois
    challenge = LnurlAuthChallenge(action=action)
    session.add(challenge)
    await session.commit()
    await session.refresh(challenge)
    return {
        "k1": challenge.k1,
        "expire": challenge.created_at
        + text(
            f"interval '{ENV.LNURL_K1_TTL_SECONDS} seconds'",
        ),
        "lnurl_auth": url_encode(
            f"{request.base_url}/auth/lnurl/callback?tag=login&k1={challenge.k1}&action={action}"
        ),
    }


@router.get("/lnurl/callback", status_code=HTTPStatus.OK)
async def lnurl_auth_callback(query: LnurlAuthCallbackIn, session: Session):
    response = {"status": "ERROR", "reason": "Unknown error"}
    # 1) k1 precisa ser esperado (emitido por nós), não reutilizado,
    #  não expirado, e action precisa bater com o que foi emitido
    action: LnurlAction = getattr(query, "action", None) or "login"
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=ENV.LNURL_K1_TTL_SECONDS
    )
    challenge = await session.scalar(
        update(LnurlAuthChallenge)
        .where(
            LnurlAuthChallenge.k1 == query.k1,
            LnurlAuthChallenge.used.is_(False),
            LnurlAuthChallenge.verified.is_(False),
            LnurlAuthChallenge.created_at >= cutoff,
        )
        .values(verified=True)
        .returning(LnurlAuthChallenge)
    )
    if not challenge:
        return {"status": "ERROR", "reason": "Invalid or expired k1"}
    if challenge.action != action:
        return {"status": "ERROR", "reason": "Action mismatch"}

    # 2) verifica assinatura (k1 assinado pela linkingPrivKey do wallet)
    if not verify(query.k1, query.key, query.sig):
        return {"status": "ERROR", "reason": "Bad Signature Error"}

    # 3) resolve/gera usuário por linkingKey (pubkey derivada por domínio)
    db_user = await session.scalar(
        select(User).where(User.publickey == query.key)
    )
    match action:
        case "register":
            if not db_user:
                with session.begin():
                    db_user = User(
                        password=None,
                        email=None,
                        affiliate_of=None,
                        nickname=None,
                        publickey=query.key,
                        login=None,
                    )
                    session.add(db_user)
                    await session.flush()
                    challenge.user_id = db_user.id
                    session.add(challenge)
                    await session.commit()
            response = {"status": "OK"}

        case "login":
            if not db_user:
                return {
                    "status": "ERROR",
                    "reason": "User not found for this linkingKey",
                }
            challenge.verified = True
            challenge.user_id = db_user.id
            session.add(challenge)
            await session.commit()
            response = {"status": "OK"}
        case "link":
            # “link” = vincular esse linkingKey a uma conta já logada
            user = await session.scalar(
                select(User).where(User.id == challenge.user_id)
            )
            user.lnurl_pubkey = query.key
            challenge.verified = True
            challenge.used = True
            session.add_all([user, challenge])
            await session.commit()
            response = {"status": "OK"}
        case "auth":
            # “auth” = autorizar uma ação stateless (sem login).
            # aqui você normalmente valida também "o que está sendo autorizado"

            challenge.verified = True
            session.add(challenge)
            await session.commit()
            response = {"status": "OK"}
        case _:
            response = {"status": "ERROR", "reason": "Unknown action"}
    return response
