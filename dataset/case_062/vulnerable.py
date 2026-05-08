"""
Case 062: CVE-2016-1000003 minimal reproduction (unsafe pickle.loads on remote payload).

Upstream: fedora-infra/mirrormanager2 mirrormanager2/xmlrpc.py `checkin`.
"""

# ---------------------------------------------------------------------------
# 上游 / exported_cve_cases
# ---------------------------------------------------------------------------
# - dataset/exported_cve_cases/case_002_CVE-2016-1000003_xmlrpc/
# - Sink: pickle.loads on attacker-controlled bytes after bz2 + URL-safe base64.
# - Reference fixed pattern: try json.loads(uncompressed) except ValueError: pickle.loads(...)
# ---------------------------------------------------------------------------

import base64
import bz2
import pickle


def read_host_config(session, config):
    """Minimal stand-in for upstream read_host_config(SESSION, config)."""
    if isinstance(config, dict) and config.get("valid") is True:
        return True, "ok:"
    return None, "bad:"


def checkin(pickledata: str) -> str:
    """
    VULNERABLE: unpickles remote-controlled bytes (code execution risk — CWE-94).
    """
    raw = pickledata.encode("ascii") if isinstance(pickledata, str) else pickledata
    uncompressed = bz2.decompress(base64.urlsafe_b64decode(raw))
    config = pickle.loads(uncompressed)
    r, message = read_host_config(None, config)
    if r is not None:
        return message + "checked in successful"
    return message + "error checking in"