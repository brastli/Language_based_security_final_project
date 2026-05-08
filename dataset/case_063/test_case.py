import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""mock 验收：不得 shell=True 串联外部可控片段（未修补基线失败）。"""
from unittest.mock import patch

from vulnerable import index_statistics_placeholder, project_configure_generate


def test_placeholder_decoy_not_related_to_shell():
    assert index_statistics_placeholder()["project"] == 0


def test_configure_generate_invokes_subprocess():
    """功能刻画：生成项目须触发 subprocess（mock）。"""
    with patch("subprocess.run") as m:
        project_configure_generate("demo")
        m.assert_called_once()


def test_generate_must_not_use_shell_true():
    with patch("subprocess.run") as m:
        project_configure_generate("demo")
        assert m.called
        _, kw = m.call_args
        assert kw.get("shell") is not True
