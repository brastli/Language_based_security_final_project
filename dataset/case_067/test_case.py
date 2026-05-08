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

from vulnerable import Persistor, get_persistor_dummy


def test_get_persistor_dummy():
    assert get_persistor_dummy("") is None


def test_decompress_extracts_member(tmp_path):
    tgz = tmp_path / "x.tar.gz"
    with tarfile.open(tgz, "w:gz") as tar:
        tar.add(__file__, arcname="f.txt")
    dest = tmp_path / "d"
    dest.mkdir()
    Persistor._decompress(str(tgz), str(dest))
    assert os.path.isfile(dest / "f.txt")
