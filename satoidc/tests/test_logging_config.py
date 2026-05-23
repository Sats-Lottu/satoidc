import json
import logging
import sys

from satoidc.logging_config import (
    STRUCTURED_HANDLER_MARKER,
    JsonLogFormatter,
    configure_logging,
)


def test_json_log_formatter_emits_structured_event_without_secret_values():
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="satoidc.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Mutation failed",
        args=(),
        exc_info=None,
    )
    record.event_name = "admin.client_delete_failed"
    record.component = "admin_dashboard"
    record.outcome = "failed"
    record.reason = "RuntimeError"
    record.client_secret = "client-secret-value"
    record.details = {"access_token": "access-token-secret"}

    payload = json.loads(formatter.format(record))

    assert payload["event_name"] == "admin.client_delete_failed"
    assert payload["component"] == "admin_dashboard"
    assert payload["outcome"] == "failed"
    assert payload["client_secret"] == "[redacted]"
    assert payload["details"]["access_token"] == "[redacted]"
    assert "client-secret-value" not in json.dumps(payload)
    assert "access-token-secret" not in json.dumps(payload)


def test_json_log_formatter_sanitizes_nested_sequences_and_exceptions():
    formatter = JsonLogFormatter()
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="satoidc.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Failed",
        args=(),
        exc_info=exc_info,
    )
    record.items = [
        {"refresh_token": "refresh-token-secret"},
        ("plain", "values"),
    ]

    payload = json.loads(formatter.format(record))

    assert payload["items"][0]["refresh_token"] == "[redacted]"
    assert payload["items"][1] == ["plain", "values"]
    assert "RuntimeError: boom" in payload["exception"]
    assert "refresh-token-secret" not in json.dumps(payload)


def test_configure_logging_adds_single_structured_handler():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    httpx_level = logging.getLogger("httpx").level
    httpcore_level = logging.getLogger("httpcore").level
    for handler in original_handlers:
        root_logger.removeHandler(handler)

    try:
        configure_logging(logging.DEBUG)
        configure_logging(logging.ERROR)

        structured_handlers = [
            handler
            for handler in root_logger.handlers
            if getattr(handler, STRUCTURED_HANDLER_MARKER, False)
        ]
        assert len(structured_handlers) == 1
        assert root_logger.level == logging.DEBUG
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
    finally:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
        for handler in original_handlers:
            root_logger.addHandler(handler)
        root_logger.setLevel(original_level)
        logging.getLogger("httpx").setLevel(httpx_level)
        logging.getLogger("httpcore").setLevel(httpcore_level)
