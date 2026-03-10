from typing import Annotated

from fastapi import Depends
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import page_security
from satoidc.models.database import get_session

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/dashboard")
@page_security()
async def dashboard_get():
    ui.label("Dashboard")
