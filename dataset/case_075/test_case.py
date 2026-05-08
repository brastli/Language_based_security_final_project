"""
case_075（CVE-2022-31137）集成测试。

Bandit 对该 vulnerable.py 的典型输出规模（供参考，非 pytest 动态扫描）：
  - 合计约 40+ 条 findings（随 Bandit 版本略有出入）
  - 规则分布大致包括：B605（shell/注入相关，占多数）、B701（Jinja autoescape）、
    B608（SQL 拼接）、B113（requests 无 timeout）、B108（临时目录）等

本文件无法也不试图为「每一条 Bandit 告警」各写一个用例，而是选取 **多条互不相同的
「用户输入 → shell/subprocess」攻击面**，用于检验修补流水线能否在一次修改中同时消除
多处同类命令注入风险（若只修一处，对应安全测试仍会失败）。

当前覆盖的 3 个独立攻击面（均为未修补时存在命令拼接）：
  1. ipbackend → funct.subprocess_execute（本地 nc|grep|awk）
  2. getcert → funct.ssh_command（openssl 命令串拼接 cert_id）
  3. nettools_icmp（localhost）→ funct.subprocess_execute（ping 命令拼接 server_to）

每个攻击面各有一对：良性行为测试 + 恶意输入下的安全 Oracle。
未打补丁前，三个「安全」用例通常会失败；全部通过后，可认为这三条面上的注入已被处理。
"""
from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

_ROOT = str(Path(__file__).resolve().parent)
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

_VALID_TOKEN = "550e8400-e29b-41d4-a716-446655440000"

# 与「多条漏洞一次性修复」验证对应的独立攻击面数量（安全测试函数个数与之对齐）
SECURITY_SURFACE_COUNT = 3


def _purge_modules():
    for name in ("vulnerable", "funct", "sql"):
        sys.modules.pop(name, None)


def _make_form(fields: dict):
    def getvalue(key, default=None):
        return fields[key] if key in fields else default

    form = MagicMock()
    form.getvalue = getvalue
    return form


def _sql_stub():
    sql = MagicMock()
    sql.check_token_exists.return_value = True
    sql.get_dick_permit.return_value = []
    sql.is_master.return_value = []

    def get_setting(key):
        return {
            "haproxy_sock_port": "9999",
            "cert_path": "/etc/haproxy/certs",
            "ssl_local_path": "ssl",
            "haproxy_dir": "/etc/haproxy",
        }.get(key, "")

    sql.get_setting.side_effect = get_setting
    sql.select_servers.return_value = []
    sql.select_metrics_http.return_value = []
    sql.select_metrics.return_value = []
    sql.select_nginx_metrics.return_value = []
    sql.select_apache_metrics.return_value = []
    sql.select_waf_metrics.return_value = []
    sql.get_hostname_by_server_ip.return_value = "localhost"
    return sql


def _funct_stub(form):
    f = MagicMock()
    f.form = form
    f.is_ip_or_dns.side_effect = lambda x: x if x else ""
    f.checkAjaxInput.return_value = False
    f.subprocess_execute.return_value = (["line1"], "")
    f.ssh_command.return_value = ""
    f.logging = MagicMock()
    f.show_backends = MagicMock()
    f.upload = MagicMock(return_value=None)
    f.server_status = MagicMock(return_value=True)
    f.versions = MagicMock(return_value={})
    f.show_installation_output = MagicMock()
    f.return_ssh_keys_path = (0, "", "", "")
    return f


def _exec_vulnerable(stdout_target):
    path = os.path.join(_ROOT, "vulnerable.py")
    spec = importlib.util.spec_from_file_location("vulnerable_case075", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["vulnerable"] = mod
    with redirect_stdout(stdout_target):
        spec.loader.exec_module(mod)


def run_script(fields: dict):
    """执行一遍 options 脚本，返回 (stdout, mock_funct, mock_sql)。"""
    _purge_modules()
    form = _make_form(fields)
    mock_funct = _funct_stub(form)
    mock_sql = _sql_stub()
    sys.modules["funct"] = mock_funct
    sys.modules["sql"] = mock_sql
    buf = io.StringIO()
    _exec_vulnerable(buf)
    return buf.getvalue(), mock_funct, mock_sql


def _payload_reflects_shell_metachars(payload: str) -> bool:
    return bool(re.search(r'[;&|`$()<>]', payload))


def _command_still_allows_injection(cmd: str, payload: str) -> bool:
    if not cmd or payload not in cmd:
        return False
    return _payload_reflects_shell_metachars(payload)


def _assert_subprocess_payload_safe(out: str, mf: MagicMock, payload: str, *, surface: str) -> None:
    if "Nice try" in out:
        return
    if not mf.subprocess_execute.called:
        return
    cmd = mf.subprocess_execute.call_args[0][0]
    assert not _command_still_allows_injection(
        cmd, payload
    ), "[%s] subprocess command still reflects unsanitized shell metacharacters" % surface


def _assert_ssh_list_payload_safe(out: str, mf: MagicMock, payload: str, *, surface: str) -> None:
    if "Nice try" in out:
        return
    if not mf.ssh_command.called:
        return
    args = mf.ssh_command.call_args[0]
    commands = args[1] if len(args) > 1 else ()
    if not commands or not isinstance(commands, (list, tuple)):
        return
    cmd = commands[0]
    if not isinstance(cmd, str):
        return
    assert not _command_still_allows_injection(
        cmd, payload
    ), "[%s] ssh command string still reflects unsanitized shell metacharacters" % surface


# --- 行为回归（合法输入）---


def test_benign_ipbackend_calls_subprocess_and_prints_rows():
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "ipbackend": "backend01",
    }
    out, mf, _ms = run_script(fields)
    assert mf.subprocess_execute.called, "expected subprocess_execute for benign ipbackend flow"
    cmd = mf.subprocess_execute.call_args[0][0]
    assert "127.0.0.1" in cmd and "9999" in cmd
    assert 'grep "backend01"' in cmd or "backend01" in cmd
    assert "line1" in out
    assert "<br>" in out


def test_benign_getcert_calls_ssh_with_openssl():
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "getcert": "server.crt",
    }
    _out, mf, _ms = run_script(fields)
    assert mf.ssh_command.called, "expected ssh_command for getcert flow"
    args = mf.ssh_command.call_args[0]
    cmds = args[1]
    assert cmds and "openssl" in cmds[0] and "server.crt" in cmds[0]


def test_benign_nettools_icmp_localhost_subprocess_ping():
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "nettools_icmp_server_from": "localhost",
        "nettools_icmp_server_to": "8.8.8.8",
        "nettools_action": "nettools_ping",
    }
    _out, mf, _ms = run_script(fields)
    assert mf.subprocess_execute.called, "expected subprocess_execute for nettools icmp localhost"
    cmd = mf.subprocess_execute.call_args[0][0]
    assert "ping" in cmd and "8.8.8.8" in cmd


# --- 安全 Oracle（恶意输入；修补后应通过）---


def test_command_injection_ipbackend_neutralized_or_blocked():
    payload = 'x"; id #'
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "ipbackend": payload,
    }
    out, mf, _ms = run_script(fields)
    _assert_subprocess_payload_safe(out, mf, payload, surface="ipbackend")


def test_command_injection_getcert_neutralized_or_blocked():
    payload = 'cert"; id #'
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "getcert": payload,
    }
    out, mf, _ms = run_script(fields)
    _assert_ssh_list_payload_safe(out, mf, payload, surface="getcert")


def test_command_injection_nettools_icmp_neutralized_or_blocked():
    payload = "8.8.8.8; id #"
    fields = {
        "serv": "127.0.0.1",
        "token": _VALID_TOKEN,
        "nettools_icmp_server_from": "localhost",
        "nettools_icmp_server_to": payload,
        "nettools_action": "nettools_ping",
    }
    out, mf, _ms = run_script(fields)
    _assert_subprocess_payload_safe(out, mf, payload, surface="nettools_icmp")
