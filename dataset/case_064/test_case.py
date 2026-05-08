import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import io
from unittest.mock import patch

from vulnerable import load_config_stream


def test_plain_yaml_mapping_roundtrip():
    buf = io.StringIO("tenable:\n  platform: tenable.io\n")
    assert load_config_stream(buf)["tenable"]["platform"] == "tenable.io"


def test_must_use_safe_load_api():
    with patch("yaml.load") as yload:
        with patch("yaml.safe_load") as ys:
            ys.return_value = {"a": 1}
            load_config_stream(io.StringIO("a: 1\n"))
            yload.assert_not_called()
            ys.assert_called_once()
