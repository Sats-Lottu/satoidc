from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, with_loader_criteria

from satoidc.models import Permission, User
from satoidc.models.database import get_session

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@ui.page("/profile", dark=True)
async def profile(session: Session, request: Request):  # noqa: PLR0915, E501
    user_id = request.session.get("user_id")
    user = await session.scalar(
        select(User)
        .options(
            joinedload(User.permissions),
            with_loader_criteria(
                Permission,
                lambda cls: (
                    (cls.disabled.is_(False))
                    & (
                        (cls.expiration_date > func.now())
                        | (cls.expiration_date.is_(None))
                    )
                ),
                include_aliases=True,
            ),
        )
        .where(User.id == UUID(user_id))
    )
    permissions = {perm.permission_type for perm in user.permissions}
    ui.label("Profile").classes("text-2xl font-bold")
    ui.separator()

    with ui.footer().classes("bg-transparent justify-end"):
        ui.label("Made with ❤️ by Sats Lottu").classes("text-sm text-gray-500")

    with ui.column().classes("w-full max-w-5xl mx-auto gap-6"):  # noqa: PLR1702,
        # Header resumido do perfil
        with ui.card().classes(
            "w-full p-6 bg-[#111827] text-white shadow-xl rounded-2xl"
        ):
            with ui.row().classes("w-full items-center justify-between"):
                with ui.column().classes("gap-2"):
                    ui.label(user.nickname or "Unnamed User").classes(
                        "text-2xl font-semibold"
                    )
                    ui.label(user.email or "No email linked").classes(
                        "text-gray-400"
                    )
                    with ui.row().classes("items-center gap-2 mt-2"):
                        if user.lnurl_pubkey:
                            ui.chip("Wallet linked", icon="link").props(
                                "color=green outline"
                            )
                        else:
                            ui.chip("No wallet", icon="link_off").props(
                                "color=red outline"
                            )
                        for perm in user.permissions:
                            ui.chip(perm.permission_type, icon="check").props(
                                "color=blue outline"
                            )
                        """ui.chip("Developer", icon="developer_mode").props(
                            "color=orange outline"
                        )
                        ui.chip("Standard user", icon="person").props(
                            "color=blue outline"
                        )"""

                with ui.column().classes("items-end gap-2"):
                    ui.button(
                        "Logout",
                        icon="logout",
                        on_click=lambda: ui.navigate.to("/logout"),
                    ).props("outline color=primary")

        # Grid principal
        with ui.row().classes("w-full gap-6 items-stretch"):
            with ui.column().classes("flex-1 min-w-[300px] gap-6"):
                # Informações pessoais
                with ui.card().classes(
                    "w-full p-5 bg-[#111827] text-white rounded-2xl shadow-lg"
                ):
                    ui.label("User Info").classes("text-xl font-semibold mb-4")
                    ui.separator().classes("mb-4")

                    with ui.row().classes(
                        "w-full items-center justify-between"
                    ):
                        with ui.column().classes("gap-1"):
                            ui.label("Nickname").classes(
                                "text-gray-400 text-sm"
                            )
                            ui.label(user.nickname or "Not set").classes(
                                "text-base"
                            )
                        ui.button(
                            "Change nickname",
                            icon="edit",
                            on_click=lambda: ui.notify(
                                "Abrir modal para alterar nickname"
                            ),
                        ).props("outline")

                    ui.separator().classes("my-3")

                    with ui.row().classes(
                        "w-full items-center justify-between"
                    ):
                        with ui.column().classes("gap-1"):
                            ui.label("Email").classes("text-gray-400 text-sm")
                            ui.label(user.email or "No email linked").classes(
                                "text-base break-all"
                            )
                        ui.button(
                            "Change email",
                            icon="mail",
                            on_click=lambda: ui.notify(
                                "Abrir modal para alterar email"
                            ),
                        ).props("outline")

                # Segurança
                with ui.card().classes(
                    "w-full p-5 bg-[#111827] text-white rounded-2xl shadow-lg"
                ):
                    ui.label("Security").classes("text-xl font-semibold mb-4")
                    ui.separator().classes("mb-4")

                    ui.label(
                        "Manage your account credentials and access methods."
                    ).classes("text-gray-400 mb-4")
                    ui.button(
                        "Change password",
                        icon="lock",
                        on_click=lambda: ui.notify(
                            "Abrir modal para alterar senha"
                        ),
                    ).props("color=primary")

                # Permissões de desenvolvedor
                with ui.card().classes(
                    "w-full p-5 bg-[#111827] text-white rounded-2xl shadow-lg"
                ):
                    ui.label("Developer Access").classes(
                        "text-xl font-semibold mb-4"
                    )
                    ui.separator().classes("mb-4")
                    if {"developer", "admin", "root"} & permissions:
                        ui.label(
                            "Your account already has developer permissions."
                        ).classes("text-green-400 mb-4")
                        ui.button(
                            "Go to Developer Dashboard",
                            icon="dashboard",
                            on_click=lambda: ui.navigate.to(
                                "/dashboard/developer"
                            ),
                        ).props("color=orange")
                    if {"admin", "root"} & permissions:
                        ui.label(
                            "Your account has admin permissions, which include"
                            " developer access."
                        ).classes("text-green-400 mb-4")
                        ui.button(
                            "Go to Admin Dashboard",
                            icon="admin_panel_settings",
                            on_click=lambda: ui.navigate.to(
                                "/dashboard/admin"
                            ),
                        ).props("color=orange")

                    if not permissions:
                        ui.label(
                            "Request access to developer features, APIs and"
                            " application registration."
                        ).classes("text-gray-400 mb-4")
                        ui.button(
                            "Request developer permissions",
                            icon="code",
                            on_click=lambda: ui.notify(
                                "Solicitação enviada para análise"
                            ),
                        ).props("color=orange outline")

            with ui.column().classes("flex-1 min-w-[300px] gap-6"):
                # Wallet / LNURL
                with ui.card().classes(
                    "w-full p-5 bg-[#111827] text-white rounded-2xl shadow-lg"
                ):
                    ui.label("Wallet Connection").classes(
                        "text-xl font-semibold mb-4"
                    )
                    ui.separator().classes("mb-4")

                    with ui.column().classes("gap-2"):
                        ui.label("LNURL Pubkey").classes(
                            "text-gray-400 text-sm"
                        )
                        ui.label(
                            user.lnurl_pubkey or "No wallet linked"
                        ).classes("text-sm break-all text-white")

                    ui.separator().classes("my-4")

                    with ui.row().classes("gap-3"):
                        if user.lnurl_pubkey:
                            ui.button(
                                "Unlink wallet",
                                icon="link_off",
                                on_click=lambda: ui.notify(
                                    "Confirmar deslinkar wallet"
                                ),
                            ).props("color=negative outline")
                            ui.button(
                                "Relink wallet",
                                icon="link",
                                on_click=lambda: ui.notify(
                                    "Iniciar novo processo de vinculação"
                                ),
                            ).props("outline")
                        else:
                            ui.button(
                                "Link wallet",
                                icon="bolt",
                                on_click=lambda: ui.notify(
                                    "Iniciar fluxo LNURL-auth"
                                ),
                            ).props("color=positive")

                # Ações rápidas
                with ui.card().classes(
                    "w-full p-5 bg-[#111827] text-white rounded-2xl shadow-lg"
                ):
                    ui.label("Quick Actions").classes(
                        "text-xl font-semibold mb-4"
                    )
                    ui.separator().classes("mb-4")

                    with ui.column().classes("w-full gap-3"):
                        ui.button(
                            "Edit nickname",
                            icon="person",
                            on_click=lambda: ui.notify(
                                "Abrir edição de nickname"
                            ),
                        ).props("outline").classes("w-full")

                        ui.button(
                            "Edit email",
                            icon="alternate_email",
                            on_click=lambda: ui.notify(
                                "Abrir edição de email"
                            ),
                        ).props("outline").classes("w-full")

                        ui.button(
                            "Change password",
                            icon="password",
                            on_click=lambda: ui.notify(
                                "Abrir edição de senha"
                            ),
                        ).props("outline").classes("w-full")

                        if user.lnurl_pubkey:
                            ui.button(
                                "Unlink wallet",
                                icon="link_off",
                                on_click=lambda: ui.notify(
                                    "Confirmar deslinkar wallet"
                                ),
                            ).props("outline color=negative").classes("w-full")
                        else:
                            ui.button(
                                "Link wallet",
                                icon="link",
                                on_click=lambda: ui.notify(
                                    "Iniciar vínculo da wallet"
                                ),
                            ).props("outline color=positive").classes("w-full")
