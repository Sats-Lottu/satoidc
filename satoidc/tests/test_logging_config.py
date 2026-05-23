import json
import logging

from satoidc.logging_config import JsonLogFormatter


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
