import satoidc.models.database as database_module


async def test_get_session_yields_async_session():
    async for session in database_module.get_session():
        assert session.is_active
        break


def test_remove_sync_session_delegates_to_scoped_session(monkeypatch):
    calls = []

    monkeypatch.setattr(
        database_module.SyncSession,
        "remove",
        lambda: calls.append("removed"),
    )

    database_module.remove_sync_session()

    assert calls == ["removed"]
