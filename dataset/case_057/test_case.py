import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""子域名 SSRF — 发起 HTTP + 校验 subdomain。"""

from unittest.mock import MagicMock, patch

import pytest

import vulnerable as v


def test_requests_expected_host_pattern():
    v.app.testing = True
    with patch("requests.get") as g:
        g.return_value = MagicMock(text="data")
        with v.app.test_request_context("/full_ssrf?subdomain=api"):
            v.full_ssrf()
        assert "api.example.com" in g.call_args[0][0]


def test_subdomain_must_reject_path_traversal_tokens():
    with pytest.raises(ValueError):
        with v.app.test_request_context("/full_ssrf?subdomain=.."):
            v.full_ssrf()
