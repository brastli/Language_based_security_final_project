import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

from unittest.mock import patch

from vulnerable import gui_health_stub, launch_webgui_with_args


def test_health_stub():
    assert gui_health_stub()["status"] == "ok"


def test_launch_invokes_subprocess_backend():
    """功能刻画：启动 GUI 须触发 subprocess.run（mock）。"""
    with patch("subprocess.run") as m:
        launch_webgui_with_args("--port 8080")
        m.assert_called_once()


def test_launch_must_not_use_shell_true():
    with patch("subprocess.run") as m:
        launch_webgui_with_args("--port 8080")
        assert m.call_args[1].get("shell") is not True
