"""
case_064 ← exported case_005_CVE-2021-21371_cli (tenable_jira/cli.py).

cli() 内 yaml.load；附带无关占位函数模拟原仓库体量。
"""

import io

import yaml


def base_config_stub():
    return {"log": {"level": "info"}}


def dict_merge_stub(a, b):
    out = dict(a)
    out.update(b)
    return out


def load_config_stream(fp):
    """VULNERABLE：等价于原 cli() 中 yaml.load(configfile, Loader=yaml.Loader)。"""
    text = fp.read() if hasattr(fp, "read") else fp
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return yaml.load(text, Loader=yaml.Loader)


def format_troubleshoot_stub(config_blob: str) -> str:
    """占位，不参与 sink。"""
    return "help:\n" + config_blob[:80]
