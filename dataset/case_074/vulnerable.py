"""
Case 074: CVE-2017-2809 minimal reproduction (unsafe yaml.load on decrypted vault text).

Upstream: tomoh1r/ansible-vault ansible_vault/api.py `Vault.load`.
"""

# ---------------------------------------------------------------------------
# 上游 / exported_cve_cases
# ---------------------------------------------------------------------------
# - dataset/exported_cve_cases/case_003_CVE-2017-2809_api/
# - Sink: yaml.load(decrypted_stream); fix: yaml.safe_load(...)
# - Bandit: B506 (unsafe yaml load)
# ---------------------------------------------------------------------------

import yaml


class _DecryptStub:
    """Stand-in for ansible VaultLib.decrypt (no ansible dependency)."""

    def decrypt(self, stream):
        if isinstance(stream, (bytes, bytearray)):
            return bytes(stream)
        if hasattr(stream, "read"):
            return stream.read()
        return stream


class Vault:
    """Minimal Vault facade — upstream also exposes dump(); omitted here."""

    def __init__(self, password):
        self.password = password
        self.vault = _DecryptStub()

    def load(self, stream):
        """VULNERABLE: arbitrary YAML constructors via UnsafeLoader."""
        raw = self.vault.decrypt(stream)
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        return yaml.load(text, Loader=yaml.UnsafeLoader)