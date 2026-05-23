import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

STANDARD_LOG_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
STRUCTURED_HANDLER_MARKER = "_satoidc_structured_handler"
REDACTED = "[redacted]"
SENSITIVE_FIELD_HINTS = (
    "password",
    "secret",
    "token",
    "private",
    "jwk",
    "authorization",
)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in STANDARD_LOG_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = _sanitize_log_value(key, value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, default=str)


def _sanitize_log_value(key: str, value: Any) -> Any:
    if any(hint in key.lower() for hint in SENSITIVE_FIELD_HINTS):
        return REDACTED if value else value
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_log_value(str(item_key), item_value)
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [
            _sanitize_log_value(key, item_value) for item_value in value
        ]
    return value


def configure_logging(level: int = logging.INFO) -> None:
    root_logger = logging.getLogger()
    if any(
        getattr(handler, STRUCTURED_HANDLER_MARKER, False)
        for handler in root_logger.handlers
    ):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    setattr(handler, STRUCTURED_HANDLER_MARKER, True)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
