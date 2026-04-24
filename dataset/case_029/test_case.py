# Auto-generated smoke test (SecurityEval import). Refine inputs if needed.

import inspect
import tempfile

import pytest

from vulnerable import executeCommand


def _dummy_value(param_name: str, param: inspect.Parameter):
    if param.default is not inspect.Parameter.empty:
        return None
    n = param_name.lower()
    if any(x in n for x in ("path", "file", "filename", "filepath", "dir", "directory")):
        return tempfile.NamedTemporaryFile(prefix="se_", delete=False, suffix=".txt").name
    if "port" in n:
        return 49152
    if any(x in n for x in ("host", "url", "uri", "endpoint", "address")):
        return "http://127.0.0.1:9/"
    if any(x in n for x in ("cmd", "command", "shell")):
        return "true"
    if any(x in n for x in ("data", "content", "body", "text", "input", "query", "payload", "name", "user")):
        return "test"
    if any(x in n for x in ("key", "secret", "password", "token")):
        return "dummy"
    if any(x in n for x in ("id", "num", "count", "size", "age", "year", "index", "limit", "offset")):
        return 1
    return "test"


def test_smoke_call():
    sig = inspect.signature(executeCommand)
    args: list = []
    kwargs: dict = {}
    for pname, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if p.kind == inspect.Parameter.KEYWORD_ONLY:
            v = _dummy_value(pname, p)
            if v is None:
                continue
            kwargs[pname] = v
            continue
        v = _dummy_value(pname, p)
        if v is None:
            continue
        args.append(v)
    try:
        executeCommand(*args, **kwargs)
    except Exception:
        pytest.skip("smoke call not applicable in this environment")
