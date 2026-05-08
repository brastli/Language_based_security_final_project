"""case_080 — CWE-502（marshal 令牌）与 CWE-78（policy-lint shell）。基线安全项失败直至修补。"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import subprocess
from unittest.mock import patch

import pytest

import vulnerable as v


@pytest.fixture(autouse=True)
def staging_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(v, "WORK_COPY_ROOT", tmp_path / "work")
    monkeypatch.setattr(v, "ARTIFACT_STAGING", tmp_path / "staging")
    (tmp_path / "work").mkdir(parents=True, exist_ok=True)


def test_json_policy_token_loads():
    b64 = v.build_json_token_b64({"tier": "gold", "flags": ["a"]})
    obj = v.pipeline_load_policy(b64)
    assert obj["tier"] == "gold"


def test_policy_format_invokes_subprocess():
    b64 = v.build_json_token_b64({"noop": True})
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
        v.dual_lane_compile(b64, "strict-ci", "rules/base.yml")
        assert run.called
        assert "policy-lint" in run.call_args[0][0] or "policy" in run.call_args[0][0]


def test_marshal_wire_format_must_be_rejected_for_untrusted_sources():
    """修补后：不得对不可信输入执行 marshal.loads。"""
    legacy = v.build_marshal_token_b64({"trusted_marker": True})
    with pytest.raises(ValueError, match="(?i)marshal|legacy|forbidden|unsupported"):
        v.pipeline_load_policy(legacy)


def test_policy_tool_must_not_run_via_login_shell_after_hardening():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_policy_format('dev"; echo CASE080_BAD #', "conf/policy.yaml")
    assert run.call_args[1].get("shell") is not True


def test_shell_command_must_not_pass_profile_metachars():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_policy_format("$(echo CASE080)", "cfg.yaml")
    cmd = run.call_args[0][0]
    assert "$(" not in cmd