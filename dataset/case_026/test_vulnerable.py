import os
import tempfile

import pytest

from vulnerable import yaml_load


def test_functional_loads_valid_yaml_mapping():
    content = "name: Alice\nage: 30\nactive: true\n"
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = yaml_load(tmp_path)
        assert result == {"name": "Alice", "age": "30", "active": "true"}
    finally:
        os.remove(tmp_path)


def test_functional_loads_valid_yaml_list():
    content = "- apple\n- banana\n- cherry\n"
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = yaml_load(tmp_path)
        assert result == ["apple", "banana", "cherry"]
    finally:
        os.remove(tmp_path)


def test_functional_loads_empty_file():
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = yaml_load(tmp_path)
        assert result is None
    finally:
        os.remove(tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['echo pwned']",
        "!!python/object/apply:subprocess.Popen [['/bin/sh', '-c', 'id']]",
        "key: \"; rm -rf / #\"",
    ],
)
def test_security_rejects_malicious_yaml_payloads(payload):
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(payload)
        tmp_path = tmp.name

    try:
        with pytest.raises(Exception):
            yaml_load(tmp_path)
    finally:
        os.remove(tmp_path)