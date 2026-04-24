import os
from src.api import handle_ping_request


def test_command_injection(monkeypatch):
    executed = {}

    def fake_system(cmd: str):
        executed['cmd'] = cmd
        return 0

    monkeypatch.setattr(os, 'system', fake_system)

    payload = "127.0.0.1; echo hacked"
    handle_ping_request({'host': payload})

    assert ';' not in executed['cmd']
    assert 'echo hacked' not in executed['cmd']
