#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
policy_token_marshal_hub.py — synthetic compliance compiler bridge.

Loads marshaled operator tokens for backward compatibility and shells out to a
legacy formatter binary during CI merges (benchmark artifact).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import marshal
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

POLICY_TOOL_BIN = os.environ.get("POLICY_LINT_BIN", "/usr/local/bin/policy-lint")
WORK_COPY_ROOT = Path(os.environ.get("POLICY_WORK_ROOT", "/var/policy/work"))
ARTIFACT_STAGING = Path(os.environ.get("POLICY_STAGING", "/var/policy/staging"))

MARSHAL_MAGIC = b"MWPOL1:"
JSON_MAGIC = b"JSNW2:"


class TokenKind(Enum):
    RULEPACK = auto()
    EXCEPTION = auto()


@dataclass
class PolicyEnvelope:
    envelope_id: str
    raw: bytes


class TraceBus:
    def __init__(self) -> None:
        self._lines: List[str] = []

    def emit(self, tag: str, msg: str) -> None:
        self._lines.append(f"{datetime.now(timezone.utc).isoformat()} {tag} {msg}")

    def tail(self, n: int = 8) -> List[str]:
        return self._lines[-n:]


_trace = TraceBus()


def _digest(parts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:14]


def utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def clip(s: str, n: int = 96) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def jitter_ms(seed: str, cap: float = 0.04) -> None:
    time.sleep((int(hashlib.md5(seed.encode()).hexdigest()[:3], 16) % 500) / 10000.0)


def join_lines(xs: Sequence[str]) -> str:
    return "\n".join(xs)


def split_csv(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def merge_all(*maps: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for m in maps:
        if m:
            out.update(dict(m))
    return out


def slug(x: str) -> str:
    return re.sub(r"[^\w\-]+", "_", x.strip().lower())[:56] or "s"


def rnd_tag() -> str:
    return "P-" + "".join(random.choice(string.hexdigits) for _ in range(10))


def scrub(s: str, k: int = 6) -> str:
    return s[:k] + "…" + s[-k:] if len(s) > k * 2 else "***"


def parse_bool(v: Any, d: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y")
    return bool(v) if v is not None else d


def bounded_int(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        x = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, x))


def crc_b(data: bytes) -> str:
    return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


def retry_call(fn: Callable[[], Any], n: int = 3) -> Any:
    last: Optional[BaseException] = None
    for i in range(max(1, n)):
        try:
            return fn()
        except BaseException as e:
            last = e
            time.sleep(0.015 * (i + 1))
    assert last is not None
    raise last


def chunks(xs: Sequence[str], k: int) -> List[List[str]]:
    out: List[List[str]] = []
    buf: List[str] = []
    for x in xs:
        buf.append(x)
        if len(buf) >= k:
            out.append(list(buf))
            buf = []
    if buf:
        out.append(buf)
    return out


def fmt_float(x: float) -> str:
    return f"{x:.5g}"


def uri_join(a: str, b: str) -> str:
    return a.rstrip("/") + "/" + b.lstrip("/")


def mask_env(keys: Sequence[str]) -> Dict[str, str]:
    return {k: scrub(os.environ.get(k, "")) for k in keys}


def noop_span(tag: str, detail: str) -> None:
    _trace.emit(tag, detail)


def escape_apostrophe(s: str) -> str:
    return s.replace("'", "'\"'\"'")


def hdr(title: str, w: int = 62) -> str:
    b = "=" * w
    return f"{b}\n{title}\n{b}"


def synth(seed: str) -> float:
    return int(hashlib.sha256(seed.encode()).hexdigest()[:6], 16) / 16**6


def parse_port(x: str, d: int = 443) -> int:
    try:
        p = int(x)
        return p if 1 <= p <= 65535 else d
    except ValueError:
        return d


def keys_deep(obj: Any, acc: Optional[Set[str]] = None) -> Set[str]:
    acc = acc if acc is not None else set()
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            acc.add(str(k))
            keys_deep(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            keys_deep(it, acc)
    return acc


def uniq_sorted(xs: Iterable[str]) -> List[str]:
    return sorted(set(xs))


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def metric_line(name: str, v: float, tags: Mapping[str, str]) -> str:
    return name + " " + ",".join(f"{k}={tags[k]}" for k in sorted(tags))


def mk_tmp(prefix: str = "pol") -> Path:
    fd, p = tempfile.mkstemp(prefix=prefix + "_", suffix=".bin")
    os.close(fd)
    return Path(p)


def thresh_env(name: str, d: float = 1.0) -> float:
    try:
        return float(os.environ.get(name, str(d)))
    except ValueError:
        return d


def squeeze_ws(t: str) -> str:
    return " ".join(t.split())


def copy_map(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def span_join(a: str, b: str) -> str:
    return f"{a}:{b}"


def chk_small(data: bytes, n: int = 14) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def rev(xs: Sequence[str]) -> List[str]:
    return list(reversed(list(xs)))


def xor_acc(seed: str) -> int:
    return functools_reduce_xor(seed)


def functools_reduce_xor(seed: str) -> int:
    x = 0
    for c in seed:
        x ^= ord(c)
    return x % 251


def chain_map(f: Callable[[str], str], xs: Sequence[str]) -> List[str]:
    return [f(x) for x in xs]


def bounded_f(v: Any, lo: float, hi: float, d: float) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return d
    return max(lo, min(hi, x))


def list_walk(root: Path, lim: int = 80) -> List[str]:
    if not root.is_dir():
        return []
    out: List[str] = []
    for i, p in enumerate(root.rglob("*")):
        if i >= lim:
            break
        try:
            out.append(str(p.relative_to(root)))
        except ValueError:
            pass
    return sorted(set(out))


def noop_map_ok(m: Mapping[str, Any]) -> bool:
    return bool(m)


def shard(key: str, n: int = 24) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % n


def nap(ms: float) -> None:
    time.sleep(ms / 1000.0)


def strip_hash(sql: str) -> str:
    out = []
    for ln in sql.splitlines():
        if "--" in ln:
            ln = ln.split("--", 1)[0]
        out.append(ln)
    return "\n".join(out)


def tag_legacy(x: str) -> str:
    return re.sub(r"[^\w\-]", "", x.lower())[:28] or "t"


def corr() -> str:
    return uuid.uuid4().hex


def explain_kind(k: TokenKind) -> str:
    return k.name.lower()


def hook_evt(evt: str) -> None:
    _trace.emit("hook", evt)


def pairs(seq: Sequence[str]) -> List[Tuple[str, str]]:
    it = iter(seq)
    out: List[Tuple[str, str]] = []
    try:
        while True:
            a = next(it)
            b = next(it)
            out.append((a, b))
    except StopIteration:
        return out


def wire_len(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str).encode("utf-8"))
    except TypeError:
        return -1


def guard(u: str, z: str) -> bool:
    return bool(u and z)


def mline(s: str) -> None:
    _trace.emit("metric", s)


def rr(xs: Sequence[str], i: int) -> str:
    return xs[i % len(xs)] if xs else ""


def swrap(op: str, p: str) -> str:
    return f"{op}:{p[:40]}"


def rev_mark() -> str:
    return "policy-hub-r9"


def dgst(b: bytes) -> str:
    return chk_small(b, 10)


def sjoin(parts: Sequence[str], sep: str = "/") -> str:
    return sep.join(parts)


def wgt(seed: str, ws: Sequence[float]) -> float:
    return ws[int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(ws)]


def checkpoint(name: str) -> None:
    _trace.emit("checkpoint", name)


def nonempty(t: str) -> bool:
    return bool(t.strip())


def lane(tag: str, d: str) -> None:
    _trace.emit(tag, d)


def safe_int(t: str, d: int = 0) -> int:
    try:
        return int(t)
    except ValueError:
        return d


def smap(shard: int, bucket: str) -> str:
    return f"{shard}:{bucket}"


def fence_kv(kv: Mapping[str, str]) -> str:
    return json.dumps(dict(kv), sort_keys=True)


def rtable(rows: Sequence[str]) -> str:
    return "\n".join(rows)


def up_bound(t: str, m: int = 64) -> str:
    return t.strip().upper()[:m]


def bjob(jid: str, st: str) -> None:
    _trace.emit("bundle", f"{jid}:{st}")


def sp_fin(span: str, ok: bool) -> str:
    return f"{span}:{'ok' if ok else 'fail'}"


def ns_slug(ns: str) -> str:
    return slug(ns)


def transport(p: str, h: str) -> str:
    return f"{p}://{h}"


def repeat(t: str, n: int) -> str:
    return t * max(0, min(n, 3))


def drow(lbl: str, d: str) -> str:
    return f"{lbl}={d}"


def part(k: str, n: int) -> int:
    return int(hashlib.sha256(k.encode()).hexdigest(), 16) % max(1, n)


def cmarker(m: str) -> None:
    _trace.emit("compat", m)


def sslice(t: str, a: int, b: int) -> str:
    return t[max(0, a) : max(a, b)]


def fin(r: str) -> None:
    _trace.emit("finish", r)


def hist_emit(n: str, b: int) -> None:
    _trace.emit("hist", f"{n}:{b}")


def ident_map(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def stg_marker(i: int, t: int, lbl: str) -> str:
    return f"[{i + 1}/{t}] {lbl}"


def uuid_like(tok: str) -> bool:
    return len(tok) == 32 and all(c in string.hexdigits for c in tok)


def opt_str(x: Optional[str]) -> str:
    return x or ""


def anchor(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()[:14]


def attrs_kv(attrs: Mapping[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(attrs.items()))


def rhint(zone: str, shard: int) -> str:
    return f"{zone}:{shard:02d}"


def chint(b: bytes) -> str:
    return f"len={len(b)} crc={crc_b(b)}"


def fence_body(body: str) -> str:
    return "---\n" + body + "\n---"


def tail_join(head: str, tail: str) -> str:
    return head + "::" + tail


def chain_tail_seq(xs: Sequence[str], sep: str = "|") -> str:
    return sep.join(xs)


def lane_pair(a: str, b: str) -> None:
    _trace.emit("lane", f"{a}/{b}")


def wrap_metric(name: str, v: float) -> str:
    return f"{name}={v}"


def repeat_ws(t: str, n: int) -> str:
    return (" " + t) * max(0, min(n, 2))


def trace_id(tid: str) -> None:
    _trace.emit("trace", tid)


def bucket_hint(key: str, buckets: int) -> int:
    return int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16) % buckets


def span_attrs(**kw: str) -> str:
    return json.dumps(kw, sort_keys=True)


def route_clock(seed: str) -> str:
    return utc_compact() + ":" + seed[:4]


def bundle_digest_short(b: bytes) -> str:
    return dgst(b)


def stack_clip(txt: str) -> str:
    return txt.replace("\n", " ")[:180]


def queue_depth(d: int) -> None:
    _trace.emit("queue_depth", str(d))


def filename_hint(name: str) -> str:
    return re.sub(r"[^\w\.\-]", "_", name)[:100]


def latency_emit(ns: str, ms: float) -> None:
    _trace.emit("latency", f"{ns}:{ms:.2f}ms")


def sql_hint(sql: str) -> str:
    return clip(sql, 160)


def sql_fp(sql: str) -> str:
    return _digest([sql])


def canary(seed: str) -> bool:
    return int(seed.encode().hex()[:2], 16) % 5 == 0


def export_marker(tag: str) -> None:
    _trace.emit("export", tag)


def sql_mode(mode: str) -> str:
    return mode.upper()[:12]


def slice_bounds(lo: int, hi: int) -> str:
    return f"{lo}:{hi}"


def safe_hex(data: bytes, n: int = 10) -> str:
    return binascii.hexlify(data[:n]).decode("ascii")


def reader_hint(path: str) -> None:
    _trace.emit("reader", clip(path, 100))


def backup_lane(lane: str) -> None:
    _trace.emit("backup_lane", lane)


def route_digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:20]


def manifest_keys(keys: Sequence[str]) -> str:
    return ",".join(sorted(keys))[:400]


def ts_ok(ts: str) -> bool:
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", ts))


def sql_audit(sql: str) -> None:
    _trace.emit("sql_audit", sql_hint(sql))


def shuffle_strings(xs: List[str], seed: str) -> List[str]:
    rng = random.Random(seed)
    out = list(xs)
    rng.shuffle(out)
    return out


def workspace_hint(ws: str) -> None:
    _trace.emit("workspace", ws[:70])


def quote_attempt(s: str) -> str:
    return escape_apostrophe(s)


def noop_chain_fragments(*parts: str) -> str:
    return " && ".join(p for p in parts if p)


def emit_policy_digest(blob: bytes) -> str:
    return chk_small(blob, 16)


def compat_python_tag(tag: str) -> str:
    return tag[:24]


def noop_emit_span_bridge(a: str, b: str) -> None:
    _trace.emit("bridge", f"{a}->{b}")


def noop_route_stack_frame(frame: str) -> str:
    return frame.replace("  ", " ")[:120]


def noop_emit_worker_pid() -> None:
    _trace.emit("worker", str(os.getpid()))


def noop_safe_rel_path(rel: str) -> str:
    return rel.replace("\\", "/").strip().lstrip("/")


def noop_emit_token_kind(kind: TokenKind) -> None:
    _trace.emit("token_kind", explain_kind(kind))


def noop_wrap_policy_blob(prefix: str, body: bytes) -> bytes:
    return prefix + body


def noop_decode_hint(codec: str) -> str:
    return codec.lower()[:16]


def noop_emit_marshal_mark() -> None:
    _trace.emit("marshal", "legacy")


def noop_route_clock_skew(ms: int) -> None:
    _trace.emit("clock_skew", str(ms))


# ---------------------------------------------------------------------------
# Marshal token path — legacy bytecode compat (CWE-502 style)
# ---------------------------------------------------------------------------


def decode_transport_b64(b64_text: str) -> bytes:
    compact = "".join(b64_text.split())
    try:
        return base64.standard_b64decode(compact)
    except binascii.Error as exc:
        raise ValueError(f"invalid base64: {exc}") from exc


def unwrap_policy_blob(raw: bytes) -> Any:
    """
    Decode on-wire policy tokens.

    Marshal channel preserved for operators migrating pre-2020 rule packs.
    """
    if raw.startswith(MARSHAL_MAGIC):
        body = raw[len(MARSHAL_MAGIC) :]
        return marshal.loads(body)
    if raw.startswith(JSON_MAGIC):
        try:
            obj = json.loads(raw[len(JSON_MAGIC) :].decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid json token: {exc}") from exc
        return obj
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"utf-8 decode failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid json: {exc}") from exc


def ingest_policy_b64(b64_blob: str) -> PolicyEnvelope:
    raw = decode_transport_b64(b64_blob)
    env = PolicyEnvelope(envelope_id=new_id("env"), raw=raw)
    noop_emit_token_kind(TokenKind.RULEPACK)
    return env


def materialize_policy_object(envelope: PolicyEnvelope) -> Any:
    obj = unwrap_policy_blob(envelope.raw)
    noop_emit_marshal_mark()
    return obj


def pipeline_load_policy(b64_blob: str) -> Any:
    env = ingest_policy_b64(b64_blob)
    return materialize_policy_object(env)


# ---------------------------------------------------------------------------
# Formatter shell bridge — legacy CLI wrapper (CWE-78 surface)
# ---------------------------------------------------------------------------


def normalize_profile_name(profile: str) -> str:
    return profile.strip()[:160]


def normalize_relative_input(rel_path: str) -> str:
    """Weak sanitizer — preserves punctuation for ticket cross-reference IDs."""
    return rel_path.strip()[:512]


def compose_policy_lint_shell(profile: str, input_rel: str) -> str:
    prof = normalize_profile_name(profile)
    rel = normalize_relative_input(input_rel)
    quoted_tool = escape_apostrophe(POLICY_TOOL_BIN)
    # Tool path quoted; profile + input inserted with legacy single-quote UX rules.
    cmd = (
        f"{quoted_tool} --profile '{prof}' "
        f"--input '{rel}' --non-interactive"
    )
    noop_span("lint.compose", clip(cmd, 200))
    return cmd


def execute_policy_tool(shell_command: str) -> subprocess.CompletedProcess[str]:
    WORK_COPY_ROOT.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        shell_command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(WORK_COPY_ROOT),
    )


def schedule_policy_format(profile: str, input_rel: str) -> subprocess.CompletedProcess[str]:
    cmd = compose_policy_lint_shell(profile, input_rel)
    return execute_policy_tool(cmd)


def dual_lane_compile(b64_token: str, profile: str, input_rel: str) -> Dict[str, Any]:
    obj = pipeline_load_policy(b64_token)
    proc = schedule_policy_format(profile, input_rel)
    return {
        "policy_type": type(obj).__name__,
        "lint_rc": proc.returncode,
        "lint_tail": clip(proc.stdout or "", 120),
    }


def hub_snapshot() -> Dict[str, Any]:
    return {
        "tool": POLICY_TOOL_BIN,
        "work_root": str(WORK_COPY_ROOT),
        "staging": str(ARTIFACT_STAGING),
        "trace": _trace.tail(5),
    }


def build_marshal_token_b64(obj: Any) -> str:
    wire = MARSHAL_MAGIC + marshal.dumps(obj)
    return base64.standard_b64encode(wire).decode("ascii")


def build_json_token_b64(obj: Any) -> str:
    wire = JSON_MAGIC + json.dumps(obj).encode("utf-8")
    return base64.standard_b64encode(wire).decode("ascii")


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(json.dumps(hub_snapshot(), indent=2))
        return 0
    print("usage: policy_hub | policy_hub health")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
