import importlib

import pytest

from satoidc.schemas.lnurl import LnurlAction, LnurlAuthCallbackIn


def test_lnurl_schemas_use_canonical_package() -> None:
    assert LnurlAuthCallbackIn.model_fields["action"].annotation == LnurlAction


def test_legacy_lnurl_schema_module_is_removed() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("satoidc.auth.lnurl_schemas")
