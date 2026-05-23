import tomllib
from pathlib import Path

FULL_LINE_COVERAGE_PERCENT = 100


def test_quality_testing_tasks_are_declared() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text("utf-8"))

    tasks = pyproject["tool"]["taskipy"]["tasks"]

    assert tasks["test_unit"] == (
        'pytest -m "not e2e and not integration and not container and not '
        'property and not load and not slow"'
    )
    assert tasks["test_property"] == (
        'pytest -m "property and not property_slow" --no-cov'
    )
    assert tasks["test_api_security"] == (
        "pytest -m api_security tests/api --no-cov"
    )
    assert tasks["test_integration"] == (
        'pytest -m "(integration or container) and not load" --no-cov'
    )
    assert tasks["test_load"].startswith(
        "locust -f tests/load/locustfile.py --headless"
    )
    assert tasks["test_all"] == 'pytest -m "not load and not slow"'
    assert tasks["coverage_html"] == "coverage html"
    assert tasks["post_test"] == "coverage html"


def test_quality_testing_markers_are_declared() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text("utf-8"))

    markers = "\n".join(pyproject["tool"]["pytest"]["ini_options"]["markers"])

    for marker in (
        "integration:",
        "container:",
        "property:",
        "property_slow:",
        "api_security:",
        "api_contract:",
        "load:",
        "slow:",
    ):
        assert marker in markers


def test_default_coverage_gate_requires_full_line_coverage() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text("utf-8"))

    coverage_report = pyproject["tool"]["coverage"]["report"]

    assert coverage_report["fail_under"] == FULL_LINE_COVERAGE_PERCENT
    assert coverage_report["show_missing"] is True
