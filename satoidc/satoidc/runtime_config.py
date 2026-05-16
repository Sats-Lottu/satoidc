from pathlib import Path
from urllib.parse import unquote

from sqlalchemy.engine import URL, make_url

PRODUCTION_ENVIRONMENTS = {"production", "prod"}
PLACEHOLDER_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
LOCAL_ISSUERS = {"http://localhost:8000", "http://127.0.0.1:8000"}


def is_production_environment(app_env: str) -> bool:
    return app_env.lower() in PRODUCTION_ENVIRONMENTS


def is_placeholder_secret(value: str | None) -> bool:
    return not value or value == PLACEHOLDER_SECRET


def is_operator_issuer_missing(value: str | None) -> bool:
    if not value or not value.strip():
        return True
    return value.rstrip("/") in LOCAL_ISSUERS


def _backend_family(url: URL) -> str:
    return url.drivername.split("+", maxsplit=1)[0]


def _sqlite_database(url: URL) -> str:
    database = unquote(url.database or "")
    if database == ":memory:":
        return database
    return str(Path(database).as_posix())


def database_url_identity(
    raw_url: str,
) -> tuple[str, str | None, int | None, str]:
    url = make_url(raw_url)
    backend = _backend_family(url)

    if backend == "sqlite":
        return (backend, None, None, _sqlite_database(url))

    return (
        backend,
        url.host,
        url.port,
        unquote((url.database or "").lstrip("/")),
    )


def database_urls_match(database_url: str, sync_database_url: str) -> bool:
    return database_url_identity(database_url) == database_url_identity(
        sync_database_url
    )


def validate_database_url_pair(
    database_url: str, sync_database_url: str
) -> None:
    if not database_urls_match(database_url, sync_database_url):
        raise ValueError(
            "DATABASE_URL and SYNC_DATABASE_URL must point to the same "
            "database"
        )
