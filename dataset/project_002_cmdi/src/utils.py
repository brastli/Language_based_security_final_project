import os
import re
import subprocess


def ping_host(host: str):
    """Ping a host without invoking a shell."""
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")

    if re.search(r"[;&|`$<>\\\n\r]", host):
        raise ValueError("invalid host")

    result = subprocess.run(["ping", "-n", "1", host], check=False)
    return result.returncode
