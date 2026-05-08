import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import os
import tarfile
from pathlib import Path

from vulnerable import get_latest_model_dummy, unpack_model


def test_latest_model_stub_returns_none_for_missing():
    assert get_latest_model_dummy("/nonexistent/path/xyz") is None


def test_unpack_extracts_archive_to_working_directory(tmp_path):
    """功能：合法 tar.gz 能展开到目录（安全修补需保留此行为并消除裸 extractall 风险，见 Bandit B202）。"""
    tarpath = tmp_path / "m.tar.gz"
    with tarfile.open(tarpath, "w:gz") as tar:
        tar.add(__file__, arcname="marker.txt")
    outdir = tmp_path / "out"
    outdir.mkdir()
    out = unpack_model(str(tarpath), working_directory=str(outdir))
    assert os.path.isfile(os.path.join(out, "marker.txt"))
