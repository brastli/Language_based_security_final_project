import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""urllib JSON — 成功解析 + 拒绝 file:// 等非 http(s) URL。"""

from unittest.mock import MagicMock, patch

import pytest

from vulnerable import readJSON


def test_reads_json_object():
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"ok": true, "n": 1}'
    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert readJSON("https://example.invalid/json") == {"ok": True, "n": 1}


def test_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        readJSON("file:///etc/passwd")
