import pytest


@pytest.mark.integration
def test_integration_marker_is_selectable() -> None:
    pytest.importorskip("testcontainers")
