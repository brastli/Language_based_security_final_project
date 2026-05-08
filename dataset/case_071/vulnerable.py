"""
case_071 ← exported case_012_CVE-2022-31507_routes (Ganga GUI routes)。

subprocess.run(..., shell=True, ...)；混入无害占位路由函数。
"""

import subprocess


def gui_health_stub():
    return {"status": "ok"}


def launch_webgui_with_args(args: str):
    """VULNERABLE：对标 subprocess.run(f\"ganga --webgui {args}\", shell=True, ...)。"""
    subprocess.run(f"ganga --webgui {args}", shell=True)


def parse_job_list_stub(raw: str):
    """占位。"""
    return raw.split(",") if raw else []
