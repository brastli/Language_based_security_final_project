from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""case_079 — CWE-89（动态 SQL）与 CWE-78（导出 shell）。基线安全用例失败直至修补。"""

import json
import os
import subprocess
from unittest.mock import patch

import pytest

import vulnerable as v


@pytest.fixture(autouse=True)
def isolated_sqlite(tmp_path, monkeypatch):
    db_path = tmp_path / "m.db"
    monkeypatch.setenv("METRICS_SQLITE_DSN", str(db_path))
    monkeypatch.setattr(v, "DB_DSN", str(db_path))
    monkeypatch.setattr(v, "EXPORT_ROOT", tmp_path / "exp")
    monkeypatch.setattr(v, "WORKSPACE_ROOT", tmp_path / "ws")
    (tmp_path / "ws" / "ten" / "a").mkdir(parents=True)
    (tmp_path / "ws" / "ten" / "a" / "f.txt").write_text("ok", encoding="utf-8")
    yield


def test_slice_query_returns_matching_rows():
    v.ingest_metric_row("acme", "cpu.load", 0.42)
    v.ingest_metric_row("acme", "cpu.idle", 0.58)
    clause = v.build_predicate_clause("acme", "cpu.")
    rows = v.run_slice_query(clause, limit=10)
    assert len(rows) == 2


def test_workspace_backup_invokes_subprocess():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "export_ok:x", "")
        v.schedule_workspace_backup("ten/a", "bundle-nightly")
        assert run.called
        cmd = run.call_args[0][0]
        assert "tar czf" in cmd


def test_dynamic_sql_must_use_parameter_binding_after_hardening():
    """修补后：metric_prefix 等字段必须经过绑定参数，不得拼接原始片段。"""
    with pytest.raises(ValueError, match="(?i)parameter|binding|invalid|injection"):
        v.orchestrate_slice(
            v.SliceRequest(tenant_id="acme", metric_prefix="x' OR '1'='1"),
            limit=50,
        )


def test_backup_must_not_use_shell_true_after_hardening():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_workspace_backup("ten/a", 'ok"; echo CASE079_BAD #')
    assert run.call_args[1].get("shell") is not True


def test_backup_command_must_not_embed_shell_metachars_in_stamp():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        v.schedule_workspace_backup("ten/a", "$(echo CASE079)")
    cmd = run.call_args[0][0]
    assert "$(" not in cmd
