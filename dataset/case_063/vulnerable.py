"""
case_063 ← exported case_004_CVE-2020-7698_views (Gerapy gerapy/server/core/views.py).

多个视图函数共用同一「shell 拼接」入口（跨函数漏洞链），并混入无关占位函数供上下文截取评测。
"""

import subprocess

PROJECTS_FOLDER = "/tmp/gerapy_projects"


def scrapyd_url_dummy(host: str, port: int) -> str:
    """占位：上游 scrapyd_url(client.ip, client.port)。"""
    return f"http://{host}:{port}/"


def index_statistics_placeholder():
    """占位：与漏洞无关的统计桩。"""
    return {"success": 0, "error": 0, "project": 0}


def _run_cli_through_shell(cmd: str):
    """共享 sink：CVE 类问题——整串交给 shell 解析。"""
    return subprocess.run(cmd, shell=True, capture_output=True)


def project_configure_generate(project_name: str):
    """configure POST 后生成项目（对标 views.project_configure 片段）。"""
    cmd = " ".join(["gerapy", "generate", project_name])
    return _run_cli_through_shell(cmd)


def project_clone(address: str, stem: str):
    """git clone 片段（对标 views.project_clone）。"""
    addr = address if address.endswith(".git") else address + ".git"
    cmd = "git clone {address} {target}".format(
        address=addr, target=f"{PROJECTS_FOLDER}/{stem}"
    )
    return _run_cli_through_shell(cmd)


def project_parse_run(args_fragment: str, project_path: str, spider_name: str):
    """gerapy parse 片段（对标 views.project_parse）。"""
    cmd = "gerapy parse {args} {proj} {spider}".format(
        args=args_fragment, proj=project_path, spider=spider_name
    )
    return _run_cli_through_shell(cmd)
