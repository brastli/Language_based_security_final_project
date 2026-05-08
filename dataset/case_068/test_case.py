import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

from unittest.mock import patch

from vulnerable import load_hparams_from_yaml_text


def test_simple_yaml_dict():
    assert load_hparams_from_yaml_text("lr: 0.01\n")["lr"] == 0.01


def test_must_use_safe_load():
    with patch("yaml.load") as yl:
        with patch("yaml.safe_load") as ys:
            ys.return_value = {"x": 1}
            load_hparams_from_yaml_text("x: 1\n")
            yl.assert_not_called()
            ys.assert_called_once()
