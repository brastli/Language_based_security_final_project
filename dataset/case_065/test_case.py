import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

from unittest.mock import patch

from vulnerable import ImportZipProject


def test_yaml_meta_reads_project_name():
    z = ImportZipProject()
    assert z.read_project_meta_from_yaml_text("project_name: Hello\n") == "Hello"


def test_must_use_safe_load_in_meta_reader():
    with patch("yaml.load") as yl:
        with patch("yaml.safe_load") as ys:
            ys.return_value = {"project_name": "X"}
            ImportZipProject().read_project_meta_from_yaml_text("x: 1\n")
            yl.assert_not_called()
            ys.assert_called_once()
