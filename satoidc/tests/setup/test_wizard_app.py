import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.status import HTTP_307_TEMPORARY_REDIRECT

from setup_wizard.__main__ import create_app

pytestmark = pytest.mark.setup


def test_setup_wizard_import_does_not_load_app_pages():
    project_dir = Path(__file__).resolve().parents[2]
    code = (
        "import sys;"
        "import setup_wizard.__main__;"
        "raise SystemExit('satoidc.routes.profile' in sys.modules)"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_dir,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_setup_wizard_builds_fastapi_app():
    app = create_app(mount_ui=False)

    assert app.title == "SatOIDC Setup Wizard"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/profile"),
        ("post", "/unknown/action"),
        ("put", "/api/settings"),
        ("patch", "/service/configuration"),
        ("delete", "/old-root"),
        ("options", "/whatever"),
    ],
)
def test_setup_wizard_redirects_unknown_routes(method: str, path: str):
    app = create_app(mount_ui=False)
    client = TestClient(app, follow_redirects=False)

    response = getattr(client, method)(path)

    assert response.status_code == HTTP_307_TEMPORARY_REDIRECT
    assert response.headers["location"] == "/"
