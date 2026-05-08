import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""GitHub API 用户 — 拉取刻画 + 校验 user_id。"""

from unittest.mock import MagicMock, patch

import pytest

import vulnerable as v


def test_fetch_github_user_profile():
    v.app.testing = True
    with patch("requests.get") as g:
        g.return_value = MagicMock(text='{"login":"octocat"}')
        with v.app.test_request_context("/user?user_id=octocat"):
            text = v.retrieve_info()
        assert "octocat" in text


def test_user_id_must_reject_non_slug_characters():
    with pytest.raises(ValueError):
        with v.app.test_request_context("/user?user_id=octocat/../evil"):
            v.retrieve_info()
