from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
case_077_incident_policy_hub — 双漏洞验收（CWE-94 eval 链 + CWE-22 路径拼接）。

良性用例：合法表达式与 jail 内的相对路径读取。
安全用例：修补后应禁止任意 Python 谓词 / 或强制路径落在 DATA_ROOT 内。
基线 vulnerable.py 不满足安全断言 → 预期 3 failed / 2 passed。
"""

from pathlib import Path

import pytest

import vulnerable as v


@pytest.fixture
def isolated_hub(monkeypatch, tmp_path: Path):
    """将 DATA_ROOT 指到临时目录并在其中放置合法附件。"""
    jail = tmp_path / "incident_store"
    jail.mkdir(parents=True)
    good_dir = jail / "vendor" / "pkg"
    good_dir.mkdir(parents=True)
    (good_dir / "manifest.json").write_bytes(b'{"ok":true}')
    monkeypatch.setattr(v, "DATA_ROOT", jail)
    return tmp_path, jail


def test_predicate_evaluates_simple_row_match(isolated_hub):
    """良性：仅使用 row 映射的简单布尔表达式。"""
    assert v.evaluate_predicate("row.get('severity') == 'HIGH'", {"severity": "HIGH"})
    assert not v.evaluate_predicate("row.get('severity') == 'HIGH'", {"severity": "LOW"})


def test_vendor_bundle_reads_only_inside_jail(isolated_hub):
    """良性：读取 jail 内嵌套路径。"""
    _tmp, jail = isolated_hub
    blob = v.open_vendor_bytes("vendor/pkg/manifest.json")
    assert b'"ok"' in blob


def test_predicate_must_not_execute_full_python_after_hardening():
    """
    修补后：不得对运营输入执行任意 Python（应改为 DSL / 受限解释器 / 白名单）。
    基线 eval 可导入标准库 → 本用例失败直至修补。
    """
    with pytest.raises(ValueError, match="(?i)unsafe|forbidden|dsl|predicate"):
        v.evaluate_predicate("__import__('os').name", {"ignored": True})


def test_open_vendor_bundle_must_reject_parent_segments_after_hardening(isolated_hub):
    """
    修补后：相对路径不得包含 `..` 或必须在解析后校验仍在 DATA_ROOT 下。
    基线可读出 jail 外预先放置的敏感文件 → 本用例失败直至修补。
    """
    tmp_path, jail = isolated_hub
    secret = tmp_path / "SECRET_LEAK.bin"
    secret.write_bytes(b"CASE077_LEAK")
    rel = "../SECRET_LEAK.bin"
    with pytest.raises(ValueError, match="(?i)path|traversal|outside|invalid"):
        v.open_vendor_bytes(rel)


def test_escape_via_nested_relative_path_must_fail_after_hardening(isolated_hub):
    """加深一层：仍不允许跳出 jail。"""
    tmp_path, jail = isolated_hub
    leak = jail.parent / "outside.txt"
    leak.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        v.open_vendor_bytes("../outside.txt")
