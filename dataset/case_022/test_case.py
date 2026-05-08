import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""npm run shell — 项目内脚本 + 禁止 shell=True。"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from vulnerable import run_npm_script


def test_runs_configured_script_with_mocked_subprocess(tmp_path):
    pkg = {"scripts": {"build": "echo build"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    with patch("subprocess.call") as m:
        m.return_value = 0
        assert run_npm_script(str(tmp_path), "build") == 0
        m.assert_called_once()


def test_must_not_use_shell_true():
    with TemporaryDirectory() as d:
        Path(d, "package.json").write_text(
            json.dumps({"scripts": {"x": "y"}}), encoding="utf-8"
        )
        with patch("subprocess.call") as m:
            m.return_value = 0
            run_npm_script(d, "x")
            _, kw = m.call_args
            assert kw.get("shell") is not True
