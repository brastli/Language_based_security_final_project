import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
A — 功能刻画（漏洞基线可用）：良性参数下，原先 os.system 收到的单行命令
   等于 \" \".join([prog] + args)，用于对照「修复前后语义」。

B — 修复验收：必须使用 subprocess.run(argv, shell=False)，且不得调用 os.system。

C — 功能等价（修复后）：argv 列表按空格拼接应与 A 中刻画的那条 shell 行一致
   （良性场景、无 shell 元字符时）。

未修复时：A 通过，B/C 失败；合理修复后：A 可不跑 subprocess 但仍可通过刻画文件单独验证，
         B/C 通过。本文件在基线上预期 B/C 失败。
"""

from unittest.mock import patch

from vulnerable import run_command


def test_functional_baseline_joined_command_line_matches_prog_and_args():
    """刻画原行为：单字符串与 \" \".join([prog] + args) 一致（mock，不执行 shell）。"""
    with patch("os.system") as mock_system:
        run_command("echo", ["hello", "world"])
        mock_system.assert_called_once_with("echo hello world")


def _assert_subprocess_argv_no_shell(prog, args):
    with patch("subprocess.run") as mock_run:
        with patch("os.system") as mock_system:
            run_command(prog, args)

            mock_system.assert_not_called()
            mock_run.assert_called_once()

            pos, kwargs = mock_run.call_args

            assert pos[0] == [prog] + list(args)
            assert kwargs.get("shell", False) is False


def test_benign_invocation_uses_subprocess_argv_list_without_shell():
    """正常输入须走 argv list，不得 shell 拼接。"""
    _assert_subprocess_argv_no_shell("echo", ["hello"])


def test_injection_payload_must_remain_single_argument_not_shell_syntax():
    """含分号的参数必须整体作为一个 argv，不得被 shell 拆成多条命令。"""
    _assert_subprocess_argv_no_shell("echo", ["hello; rm -rf /tmp/test"])


def test_subprocess_argv_join_matches_legacy_shell_line_for_benign_tokens():
    """
    C — 修复后 argv 若等于 [prog] + args，则 \" \".join(argv) 与 A 段刻画的 shell 行一致。
    """
    prog, args_list = "echo", ["hello", "world"]
    expected_line = " ".join([prog] + args_list)
    with patch("subprocess.run") as mock_run:
        with patch("os.system") as mock_sys:
            run_command(prog, args_list)
            mock_sys.assert_not_called()
            argv = mock_run.call_args[0][0]
            assert argv == [prog] + args_list
            assert " ".join(argv) == expected_line
