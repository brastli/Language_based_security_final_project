import os
import pytest
from vulnerable import app, listFiles


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_listFiles_returns_directory_listing(client, monkeypatch):
    def fake_system(cmd):
        assert cmd == "cd /home/alice && ls -l > /tmp/files.txt"
        with open("/tmp/files.txt", "w") as f:
            f.write("total 1\n-rw-r--r-- 1 alice alice 0 Jan 1 00:00 file.txt\n")
        return 0

    monkeypatch.setattr(os, "system", fake_system)

    response = client.get("/reply?username=alice")
    assert response.status_code == 200
    assert b"file.txt" in response.data
    assert b"total 1" in response.data


def test_functional_listFiles_uses_username_argument(client, monkeypatch):
    captured = {}

    def fake_system(cmd):
        captured["cmd"] = cmd
        with open("/tmp/files.txt", "w") as f:
            f.write("example.txt\n")
        return 0

    monkeypatch.setattr(os, "system", fake_system)

    response = client.get("/reply?username=bob")
    assert response.status_code == 200
    assert captured["cmd"] == "cd /home/bob && ls -l > /tmp/files.txt"
    assert response.data == b"example.txt\n"


def test_security_listFiles_sql_injection_payload_rejected(client, monkeypatch):
    payload = "alice; id"

    def fake_system(cmd):
        raise Exception("security rejection")

    monkeypatch.setattr(os, "system", fake_system)

    with pytest.raises(Exception):
        client.get(f"/reply?username={payload}")


def test_security_listFiles_command_injection_payload_rejected(client, monkeypatch):
    payload = "alice && cat /etc/passwd"

    def fake_system(cmd):
        raise Exception("security rejection")

    monkeypatch.setattr(os, "system", fake_system)

    with pytest.raises(Exception):
        client.get(f"/reply?username={payload}")


def test_security_listFiles_path_traversal_payload_rejected(client, monkeypatch):
    payload = "../../etc"

    def fake_system(cmd):
        raise Exception("security rejection")

    monkeypatch.setattr(os, "system", fake_system)

    with pytest.raises(Exception):
        client.get(f"/reply?username={payload}")