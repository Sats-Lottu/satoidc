from typing import AsyncIterator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

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

db = SessionLocal()
