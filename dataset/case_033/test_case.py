import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""base64 + exec — POST 路径可达 + 禁止对用户串 exec。"""

import base64
import inspect
from unittest.mock import patch

import vulnerable as v


def test_post_decodes_first_name_and_runs_exec():
    v.app.testing = True
    token = base64.b64encode(b"alice").decode("ascii")
    with patch("builtins.exec") as ex:
        with v.app.test_client() as client:
            client.post(f"/execute?first_name={token}")
        ex.assert_called()


def test_must_not_use_exec_on_user_controlled_string():
    src = inspect.getsource(v.code_execution)
    assert "exec(" not in src
