from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
case_076_internal_export_pipeline — 验收测试（双漏洞：CWE-502 兼容 pickle + CWE-78 shell 拼接）。

设计意图：
- 「良性」用例：JSON 线路 + 普通 export label，在 mock subprocess 下应正常工作。
- 「安全」用例：对应修补后应拒绝 pickle 兼容路径 / 禁止对用户 label 使用 shell=True 或未净化的拼接。
  当前 vulnerable.py 基线**不满足**这些安全断言（刻意），修补通过后再跑应变绿。
"""


import pickle
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vulnerable import (
    _COMPAT_MARKER_PICKLE,
    build_json_job_blob,
    build_pickled_job_blob,
    format_job_blob_for_cli,
    ingest_job_from_base64,
    materialize_job_dict,
    submit_export_ticket,
)


# --- 良性：JSON 任务 + 普通标签 ---


def test_json_legacy_job_materializes_without_pickle_branch():
    payload = {"kind": "noop", "priority": 1}
    b64 = build_json_job_blob(payload)
    env = materialize_job_dict(ingest_job_from_base64(b64))
    assert env.decoded_payload == payload


def test_benign_export_calls_subprocess_with_dataset_and_label():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr=""
        )
        submit_export_ticket("warehouse/sales_v3", "nightly-export")
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "warehouse/sales_v3" in cmd or "sales_v3" in cmd
        assert "nightly-export" in cmd


# --- 安全：修补后预期 ---


def test_legacy_pickle_wire_format_must_be_rejected():
    """
    修补后：对外部/不可信入口不应再接受 PICKLE_V1 线路。
    基线仍会成功反序列化 → 本断言在基线失败。
    """
    wire_dict = {"trusted_job": True}
    b64 = build_pickled_job_blob(wire_dict)
    raw = ingest_job_from_base64(b64).raw_blob
    assert raw.startswith(_COMPAT_MARKER_PICKLE)
    with pytest.raises(ValueError, match="(?i)pickle|legacy|unsupported|forbidden"):
        materialize_job_dict(ingest_job_from_base64(b64))


def test_export_sidecar_must_not_use_shell_or_must_escape_user_label():
    """
    修补后：对用户 export_label 不得使用 shell=True，或必须等价安全构造（argv 列表 + shell=False）。
    基线使用 shell=True → 本断言在基线失败。
    """
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        submit_export_ticket(
            "dataset-main",
            'prod"; echo CASE076_INJECTION_TEST #',
        )
    kwargs = mock_run.call_args[1]
    shell_flag = kwargs.get("shell")
    assert shell_flag is not True, "shell=True with partly user-controlled composite command"


def test_pickle_gadget_reduce_must_not_run_for_untrusted_blob():
    """
    修补后：即便线路仍含魔术字节，也不得调用 pickle.loads（或必须换成安全白名单解码）。
    基线会执行 __reduce__ → fired == True → 期望修补后 fired 不再为 True。
    """

    class Gadget:
        fired = False

        def __reduce__(self):
            Gadget.fired = True
            return (dict, ([],))

    raw = _COMPAT_MARKER_PICKLE + pickle.dumps(Gadget())
    b64 = format_job_blob_for_cli(raw)
    materialize_job_dict(ingest_job_from_base64(b64))
    assert not Gadget.fired, "unpickle gadget executed; arbitrary code deserialization path still present"
