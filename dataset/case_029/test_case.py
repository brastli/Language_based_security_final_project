import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""Flask os.system — POST 命令刻画 + 路由处理不得保留 os.system。"""

import inspect
from unittest.mock import patch

import vulnerable as v


def test_post_command_triggers_system_call():
    v.app.testing = True
    with patch("os.system") as m:
        with v.app.test_client() as client:
            client.post("/command?action=echo+ok")
        m.assert_called_once()


def test_route_must_not_use_os_system():
    src = inspect.getsource(v.executeCommand)
    assert "os.system" not in src
