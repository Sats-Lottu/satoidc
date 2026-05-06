from typing import AsyncIterator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from satoidc.settings import ENV

engine = create_async_engine(ENV.DATABASE_URL)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session


connect_args = {}
if ENV.SYNC_DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

sync_engine = create_engine(ENV.SYNC_DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=sync_engine
)
SyncSession = scoped_session(SessionLocal)

# Authlib's SQLAlchemy integration is synchronous. Keep it isolated behind a
# thread-local session registry instead of sharing one process-global Session.
db = SyncSession


def remove_sync_session() -> None:
    SyncSession.remove()
