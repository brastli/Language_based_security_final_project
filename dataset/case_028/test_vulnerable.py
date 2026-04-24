import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from vulnerable import extract_tar


def _create_tar_with_members(tar_path, members):
    with tarfile.open(tar_path, "w") as tar:
        for name, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))


import io


def test_functional_extract_tar_single_file(tmp_path):
    tar_path = tmp_path / "single.tar"
    member_name = "hello.txt"
    member_content = "hello world"

    with tarfile.open(tar_path, "w") as tar:
        data = member_content.encode("utf-8")
        info = tarfile.TarInfo(name=member_name)
        info.size = len(data)
        tar.addfile(info, fileobj=io.BytesIO(data))

    extract_tar(str(tar_path))

    extracted = Path("/tmp") / member_name
    assert extracted.exists()
    assert extracted.read_text() == member_content
    extracted.unlink()


def test_functional_extract_tar_multiple_files(tmp_path):
    tar_path = tmp_path / "multi.tar"
    members = {
        "dir1/file1.txt": "alpha",
        "dir2/file2.txt": "beta",
    }

    with tarfile.open(tar_path, "w") as tar:
        for name, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))

    extract_tar(str(tar_path))

    for name, content in members.items():
        extracted = Path("/tmp") / name
        assert extracted.exists()
        assert extracted.read_text() == content
        extracted.unlink()
        parent = extracted.parent
        while parent != Path("/tmp") and parent.exists():
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


def test_security_rejects_absolute_path_member(tmp_path):
    tar_path = tmp_path / "abs.tar"
    with tarfile.open(tar_path, "w") as tar:
        data = b"bad"
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = len(data)
        tar.addfile(info, fileobj=io.BytesIO(data))

    with pytest.raises(Exception):
        extract_tar(str(tar_path))


def test_security_rejects_path_traversal_member(tmp_path):
    tar_path = tmp_path / "traversal.tar"
    with tarfile.open(tar_path, "w") as tar:
        data = b"bad"
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = len(data)
        tar.addfile(info, fileobj=io.BytesIO(data))

    with pytest.raises(Exception):
        extract_tar(str(tar_path))


def test_security_rejects_command_injection_member(tmp_path):
    tar_path = tmp_path / "cmdinj.tar"
    malicious_names = [
        "safe;rm -rf /tmp/pwned.txt",
        "safe|cat /etc/passwd",
        "safe$(touch /tmp/pwned.txt)",
    ]

    for name in malicious_names:
        with tarfile.open(tar_path, "w") as tar:
            data = b"bad"
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))

        with pytest.raises(Exception):
            extract_tar(str(tar_path))