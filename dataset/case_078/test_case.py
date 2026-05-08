from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
case_078_connector_relay_gateway — CWE-918（中继拉取 URL）+ CWE-78（bundle shell）。

良性：mock urllib.request.urlopen / subprocess.run。
安全：修补后应拦截敏感主机 URL；bundle 导出不得 shell=True 或未净化 label。
基线预期：3 failed / 2 passed。
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import vulnerable as v


def _urlopen_context(body: bytes):
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = body
    cm.__exit__.return_value = None
    return cm


def test_partner_manifest_fetch_happy_path():
    manifest = {"service": "billing", "version": 3}
    with patch("vulnerable.urlopen") as uo:
        uo.return_value = _urlopen_context(json.dumps(manifest).encode("utf-8"))
        out = v.ingest_partner_manifest("https://partner.vendor.example/api/manifest.json")
        assert out["service"] == "billing"
        uo.assert_called_once()


def test_bundle_export_invokes_subprocess_for_workspace():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "done:x", "")
        v.schedule_bundle_export("tenant_acme/logs/current", "nightly-01")
        assert run.called
        cmd = run.call_args[0][0]
        assert "tar czf" in cmd or ".tar.gz" in cmd


def test_cloud_metadata_url_must_be_rejected_before_fetch():
    """修补后：禁止访问链路本地 / 云元数据等敏感目标。"""
    with patch("vulnerable.urlopen") as uo:
        uo.return_value = _urlopen_context(b"{}")
        with pytest.raises(ValueError, match="(?i)metadata|link-local|169|blacklist|private"):
            v.ingest_partner_manifest("http://169.254.169.254/latest/meta-data/")
    uo.assert_not_called()


def test_bundle_export_must_not_use_shell_true_after_hardening():
    """修补后：应以 argv 列表调用或移除登录 shell，对用户 label 使用严格净化。"""
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_bundle_export("safe/subdir", 'ok"; echo CASE078_BAD #')
    assert run.call_args[1].get("shell") is not True


def test_bundle_command_must_escape_or_reject_shell_metachars_in_label():
    """修补后：构造命令串时不得保留可导致命令注入的 meta 字符。"""
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_bundle_export("safe/subdir", "$(echo CASE078_INJECT)")
    cmd = run.call_args[0][0]
    assert "$(" not in cmd and "`" not in cmd, "user-controlled label reflected in shell metacharacters"
