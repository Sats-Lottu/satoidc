from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import SetupState

SETUP_STATE_ROW_ID = 1
SETUP_STATE_VERSION = 1

RECOVERABLE_ACQUIRE_STATES = frozenset(
    {"not_started", "in_progress", "ready_to_apply", "failed", "locked"}
)


@dataclass(frozen=True)
class SetupLockDiagnostics:
    current_state: str
    message: str
    last_error: str | None = None


class SetupLockUnavailableError(RuntimeError):
    def __init__(self, diagnostics: SetupLockDiagnostics) -> None:
        super().__init__(diagnostics.message)
        self.diagnostics = diagnostics


@dataclass(frozen=True)
class SetupExecutionLock:
    state_id: int
    actor: str


@dataclass(frozen=True)
class SetupStateTransition:
    state: str
    completed_by: str | None
    config_hash: str | None
    last_error: str | None
    completed_at: datetime | None


async def get_setup_state(session: AsyncSession) -> SetupState | None:
    return await session.get(SetupState, SETUP_STATE_ROW_ID)


async def acquire_setup_lock(
    session: AsyncSession, *, actor: str = "system"
) -> SetupExecutionLock:
    state = await _acquire_existing_setup_state(session)
    if state is None:
        current_state = await get_setup_state(session)
        if current_state is None:
            state = await _create_applying_setup_state(session)
    if state is None:
        await _raise_locked(session)

    await session.commit()
    return SetupExecutionLock(state_id=state.id, actor=actor)


async def release_setup_lock(
    session: AsyncSession,
    lock: SetupExecutionLock,
    *,
    completed_by: str | None = None,
    config_hash: str | None = None,
) -> SetupState:
    state = await _transition_applying_state(
        session,
        lock,
        SetupStateTransition(
            state="completed",
            completed_by=completed_by or lock.actor,
            config_hash=config_hash,
            last_error=None,
            completed_at=datetime.now(timezone.utc),
        ),
    )
    await session.commit()
    return state


async def fail_setup_lock(
    session: AsyncSession,
    lock: SetupExecutionLock,
    *,
    error: str,
) -> SetupState:
    state = await _transition_applying_state(
        session,
        lock,
        SetupStateTransition(
            state="failed",
            completed_by=None,
            config_hash=None,
            last_error=error,
            completed_at=None,
        ),
    )
    await session.commit()
    return state


async def _acquire_existing_setup_state(
    session: AsyncSession,
) -> SetupState | None:
    return await session.scalar(
        update(SetupState)
        .where(
            SetupState.id == SETUP_STATE_ROW_ID,
            SetupState.state.in_(RECOVERABLE_ACQUIRE_STATES),
        )
        .values(
            state="applying",
            version=SETUP_STATE_VERSION,
            last_error=None,
            completed_at=None,
            completed_by=None,
        )
        .returning(SetupState)
        .execution_options(
            synchronize_session=False, populate_existing=True
        )
    )


async def _create_applying_setup_state(
    session: AsyncSession,
) -> SetupState | None:
    state = SetupState(state="applying", version=SETUP_STATE_VERSION)
    session.add(state)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return await _acquire_existing_setup_state(session)
    return state


async def _transition_applying_state(
    session: AsyncSession,
    lock: SetupExecutionLock,
    transition: SetupStateTransition,
) -> SetupState:
    transitioned = await session.scalar(
        update(SetupState)
        .where(
            SetupState.id == lock.state_id,
            SetupState.state == "applying",
        )
        .values(
            state=transition.state,
            completed_by=transition.completed_by,
            config_hash=transition.config_hash,
            last_error=transition.last_error,
            completed_at=transition.completed_at,
        )
        .returning(SetupState)
        .execution_options(
            synchronize_session=False, populate_existing=True
        )
    )
    if transitioned is None:
        await _raise_locked(session)
    return transitioned


async def _raise_locked(session: AsyncSession) -> None:
    current_state = await session.scalar(
        select(SetupState).where(SetupState.id == SETUP_STATE_ROW_ID)
    )
    if current_state is None:
        diagnostics = SetupLockDiagnostics(
            current_state="missing",
            message="Setup lock could not be acquired.",
        )
    elif current_state.state == "completed":
        diagnostics = SetupLockDiagnostics(
            current_state=current_state.state,
            message="Setup has already completed.",
            last_error=current_state.last_error,
        )
    else:
        diagnostics = SetupLockDiagnostics(
            current_state=current_state.state,
            message="Setup is locked by another setup attempt.",
            last_error=current_state.last_error,
        )
    raise SetupLockUnavailableError(diagnostics)
