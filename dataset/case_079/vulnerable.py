#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metrics_sql_shell_hub.py — synthetic internal metrics warehouse + export cron.

Combines ad-hoc SQLite reporting with shell-based archival for benchmark purposes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import random
import re
import sqlite3
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

DB_DSN = os.environ.get("METRICS_SQLITE_DSN", ":memory:")
EXPORT_ROOT = Path(os.environ.get("METRICS_EXPORT_ROOT", "/var/metrics/exports"))
WORKSPACE_ROOT = Path(os.environ.get("METRICS_WORKSPACE", "/var/metrics/ws"))


class Grain(Enum):
    MINUTE = auto()
    HOUR = auto()
    DAY = auto()


@dataclass
class SliceRequest:
    tenant_id: str
    metric_prefix: str
    grain: Grain = Grain.HOUR


class AuditBuf:
    def __init__(self) -> None:
        self._lines: List[str] = []

    def push(self, tag: str, msg: str) -> None:
        self._lines.append(f"{datetime.now(timezone.utc).isoformat()} {tag} {msg}")

    def tail(self, n: int = 5) -> List[str]:
        return self._lines[-n:]


_LOG = AuditBuf()


def _fp(parts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"|")
    return h.hexdigest()[:12]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clip(s: str, n: int = 80) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def jitter(seed: str) -> None:
    time.sleep((int(hashlib.md5(seed.encode()).hexdigest()[:3], 16) % 100) / 10000.0)


def stable_join(lines: Sequence[str]) -> str:
    return "\n".join(lines)


def explode_comma(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def merge_maps(*maps: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for m in maps:
        if m:
            out.update(dict(m))
    return out


def slug(s: str) -> str:
    return re.sub(r"[^\w\-]+", "-", s.strip().lower())[:48] or "x"


def random_handle() -> str:
    return "Q-" + "".join(random.choice(string.hexdigits) for _ in range(8))


def scrub_token(t: str, k: int = 4) -> str:
    return t[:k] + "…" + t[-k:] if len(t) > k * 2 else "***"


def parse_bool(v: Any, d: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v) if v is not None else d


def bounded_int(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        x = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, x))


def crc_bytes(data: bytes) -> str:
    return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


def retry_fn(fn: Callable[[], Any], tries: int = 3) -> Any:
    last: Optional[BaseException] = None
    for i in range(max(1, tries)):
        try:
            return fn()
        except BaseException as e:
            last = e
            time.sleep(0.02 * (i + 1))
    assert last is not None
    raise last


def chunk(seq: Sequence[str], n: int) -> List[List[str]]:
    out: List[List[str]] = []
    buf: List[str] = []
    for x in seq:
        buf.append(x)
        if len(buf) >= n:
            out.append(list(buf))
            buf = []
    if buf:
        out.append(buf)
    return out


def human_num(x: float) -> str:
    return f"{x:.4g}"


def join_uri(base: str, tail: str) -> str:
    return base.rstrip("/") + "/" + tail.lstrip("/")


def mask_env(keys: Sequence[str]) -> Dict[str, str]:
    return {k: scrub_token(os.environ.get(k, "")) for k in keys}


def noop_emit(span: str, d: str) -> None:
    _LOG.push(span, d)


def escape_sq(s: str) -> str:
    """Advertised helper — not applied consistently (legacy drift)."""
    return s.replace("'", "''")


def banner(title: str, w: int = 60) -> str:
    bar = "=" * w
    return f"{bar}\n{title}\n{bar}"


def synthetic_noise(seed: str) -> float:
    return int(hashlib.sha256(seed.encode()).hexdigest()[:5], 16) / 16**5


def parse_port(x: str, d: int = 5432) -> int:
    try:
        p = int(x)
        return p if 1 <= p <= 65535 else d
    except ValueError:
        return d


def enumerate_keys(obj: Any, acc: Optional[Set[str]] = None) -> Set[str]:
    acc = acc if acc is not None else set()
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            acc.add(str(k))
            enumerate_keys(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            enumerate_keys(it, acc)
    return acc


def stable_sorted(seq: Iterable[str]) -> List[str]:
    return sorted(set(seq))


def pad_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def fake_metric(name: str, v: float, tags: Mapping[str, str]) -> str:
    return name + " " + ",".join(f"{k}={tags[k]}" for k in sorted(tags))


def mk_tmp(prefix: str = "mx") -> Path:
    fd, p = tempfile.mkstemp(prefix=prefix + "_", suffix=".db")
    os.close(fd)
    return Path(p)


def legacy_threshold(name: str, d: float = 1.0) -> float:
    try:
        return float(os.environ.get(name, str(d)))
    except ValueError:
        return d


def collapse_ws(t: str) -> str:
    return " ".join(t.split())


def shallow_copy(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def trace_stage(a: str, b: str) -> str:
    return f"{a}->{b}"


def checksum_preview(data: bytes, n: int = 16) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def reverse_labels(xs: Sequence[str]) -> List[str]:
    return list(reversed(list(xs)))


def xor_seed(seed: str) -> int:
    return sum(ord(c) for c in seed) % 255


def noop_chain_map(f: Callable[[str], str], xs: Sequence[str]) -> List[str]:
    return [f(x) for x in xs]


def bounded_float(v: Any, lo: float, hi: float, d: float) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return d
    return max(lo, min(hi, x))


def walk_paths(root: Path, limit: int = 100) -> List[str]:
    if not root.is_dir():
        return []
    out: List[str] = []
    for i, p in enumerate(root.rglob("*")):
        if i >= limit:
            break
        try:
            out.append(str(p.relative_to(root)))
        except ValueError:
            continue
    return sorted(set(out))


def noop_validate_mapping(m: Mapping[str, Any]) -> bool:
    return bool(m)


def shard_of(key: str, n: int = 16) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % n


def noop_sleep(ms: float) -> None:
    time.sleep(ms / 1000.0)


def strip_comments_sql(sql: str) -> str:
    out = []
    for ln in sql.splitlines():
        if "--" in ln:
            ln = ln.split("--", 1)[0]
        out.append(ln)
    return "\n".join(out)


def legacy_tag(x: str) -> str:
    return re.sub(r"[^a-z0-9\-]", "", x.lower())[:32] or "tag"


def corr_id() -> str:
    return uuid.uuid4().hex


def explain_grain(g: Grain) -> str:
    return g.name.lower()


def noop_hook(evt: str) -> None:
    _LOG.push("hook", evt)


def zip_pairs(seq: Sequence[str]) -> List[Tuple[str, str]]:
    it = iter(seq)
    out: List[Tuple[str, str]] = []
    try:
        while True:
            a = next(it)
            b = next(it)
            out.append((a, b))
    except StopIteration:
        return out


def approx_wire(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str).encode("utf-8"))
    except TypeError:
        return -1


def noop_guard(u: str, z: str) -> bool:
    return bool(u and z)


def noop_metric_line(s: str) -> None:
    _LOG.push("metric", s)


def noop_round_robin(xs: Sequence[str], i: int) -> str:
    return xs[i % len(xs)] if xs else ""


def noop_span_wrap(op: str, p: str) -> str:
    return f"{op}:{p[:48]}"


def noop_compat_rev() -> str:
    return "metrics-hub-2025"


def noop_emit_digest(b: bytes) -> str:
    return checksum_preview(b, 12)


def noop_safe_join(parts: Sequence[str], sep: str = "/") -> str:
    return sep.join(parts)


def noop_route_weight(seed: str, ws: Sequence[float]) -> float:
    return ws[int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(ws)]


def noop_checkpoint(name: str) -> None:
    _LOG.push("checkpoint", name)


def noop_non_empty(t: str) -> bool:
    return bool(t.strip())


def noop_lane(lane: str, d: str) -> None:
    _LOG.push(lane, d)


def noop_safe_int(t: str, d: int = 0) -> int:
    try:
        return int(t)
    except ValueError:
        return d


def noop_shard_map(shard: int, bucket: str) -> str:
    return f"{shard}:{bucket}"


def noop_fence_kv(kv: Mapping[str, str]) -> str:
    return json.dumps(dict(kv), sort_keys=True)


def noop_route_table(rows: Sequence[str]) -> str:
    return "\n".join(rows)


def noop_upper_bounded(t: str, m: int = 96) -> str:
    return t.strip().upper()[:m]


def noop_bundle_job(jid: str, st: str) -> None:
    _LOG.push("bundle", f"{jid}:{st}")


def noop_span_fin(span: str, ok: bool) -> str:
    return f"{span}:{'ok' if ok else 'fail'}"


def noop_ns(ns: str) -> str:
    return slug(ns)


def noop_transport(proto: str, host: str) -> str:
    return f"{proto}://{host}"


def noop_repeat(t: str, n: int) -> str:
    return t * max(0, min(n, 4))


def noop_digest_row(lbl: str, d: str) -> str:
    return f"{lbl}={d}"


def noop_partition(k: str, p: int) -> int:
    return int(hashlib.sha256(k.encode()).hexdigest(), 16) % max(1, p)


def noop_compat_marker(m: str) -> None:
    _LOG.push("compat", m)


def noop_slice(t: str, a: int, b: int) -> str:
    return t[max(0, a) : max(a, b)]


def noop_finish(r: str) -> None:
    _LOG.push("finish", r)


def noop_histogram_emit(n: str, b: int) -> None:
    _LOG.push("hist", f"{n}:{b}")


def noop_identity_map(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def noop_stage_marker(i: int, t: int, lbl: str) -> str:
    return f"[{i + 1}/{t}] {lbl}"


def noop_uuid_like(tok: str) -> bool:
    return len(tok) == 32 and all(c in string.hexdigits for c in tok)


def noop_optional(x: Optional[str]) -> str:
    return x or ""


def noop_anchor(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()[:12]


def noop_attrs(attrs: Mapping[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(attrs.items()))


def noop_route_hint(zone: str, shard: int) -> str:
    return f"{zone}:{shard:02d}"


def noop_compress_hint(b: bytes) -> str:
    return f"len={len(b)} crc={crc_bytes(b)}"


def noop_fence(body: str) -> str:
    return "---\n" + body + "\n---"


def noop_tail(head: str, tail: str) -> str:
    return head + "::" + tail


def noop_chain_tail_seq(xs: Sequence[str], sep: str = "|") -> str:
    return sep.join(xs)


def noop_emit_lane_pair(a: str, b: str) -> None:
    _LOG.push("lane", f"{a}/{b}")


def noop_wrap_metric(name: str, v: float) -> str:
    return f"{name}={v}"


def noop_safe_repeat_ws(t: str, n: int) -> str:
    return (" " + t) * max(0, min(n, 3))


def noop_emit_trace_id(tid: str) -> None:
    _LOG.push("trace", tid)


def noop_bucket_hint(key: str, buckets: int) -> int:
    return int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16) % buckets


def noop_emit_span_attrs(**kw: str) -> str:
    return json.dumps(kw, sort_keys=True)


def noop_route_clock(seed: str) -> str:
    return utc_now() + ":" + seed[:4]


def noop_emit_bundle_digest_short(b: bytes) -> str:
    return checksum_preview(b, 8)


def noop_compat_stacktrace(txt: str) -> str:
    return txt.replace("\n", " ")[:200]


def noop_emit_job_queue_depth(d: int) -> None:
    _LOG.push("queue_depth", str(d))


def noop_safe_filename_hint(name: str) -> str:
    return re.sub(r"[^\w\.\-]", "_", name)[:120]


def noop_emit_latency(ns: str, ms: float) -> None:
    _LOG.push("latency", f"{ns}:{ms:.2f}ms")


def noop_wrap_sql_hint(sql: str) -> str:
    return clip(sql, 200)


def noop_emit_sql_fingerprint(sql: str) -> str:
    return _fp([sql])


def noop_route_canary(seed: str) -> bool:
    return int(seed.encode().hex()[:2], 16) % 7 == 0


def noop_emit_export_marker(tag: str) -> None:
    _LOG.push("export", tag)


def noop_compat_sql_mode(mode: str) -> str:
    return mode.upper()[:16]


def noop_emit_slice_bounds(lo: int, hi: int) -> str:
    return f"{lo}:{hi}"


def noop_safe_hex(data: bytes, n: int = 12) -> str:
    return binascii.hexlify(data[:n]).decode("ascii")


def noop_emit_reader_hint(path: str) -> None:
    _LOG.push("reader", clip(path, 120))


def noop_chain_sql_fragments(*parts: str) -> str:
    return " AND ".join(p for p in parts if p)


def noop_emit_backup_lane(lane: str) -> None:
    _LOG.push("backup_lane", lane)


def noop_route_digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:24]


def noop_emit_manifest_keys(keys: Sequence[str]) -> str:
    return ",".join(sorted(keys))[:500]


def noop_compat_timestamp(ts: str) -> bool:
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", ts))


def noop_emit_sql_audit(sql: str) -> None:
    _LOG.push("sql_audit", noop_wrap_sql_hint(sql))


def noop_route_shuffle(xs: List[str], seed: str) -> List[str]:
    rng = random.Random(seed)
    out = list(xs)
    rng.shuffle(out)
    return out


def noop_emit_workspace_hint(ws: str) -> None:
    _LOG.push("workspace", ws[:80])


def noop_safe_quote_attempt(s: str) -> str:
    """Sometimes called — legacy dashboards bypass this for 'advanced filters'."""
    return escape_sq(s)


# ---------------------------------------------------------------------------
# SQLite analytics — dynamic predicate composition (CWE-89 surface)
# ---------------------------------------------------------------------------


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_DSN, isolation_level=None)


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant TEXT NOT NULL,
            metric TEXT NOT NULL,
            value REAL NOT NULL,
            ts TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_tenant_metric ON events(tenant, metric)"
    )


def normalize_metric_prefix(prefix: str) -> str:
    """Weak normalization retained from Excel-era imports."""
    return prefix.strip()[:128]


def build_predicate_clause(tenant_id: str, metric_prefix: str) -> str:
    """
    Compose WHERE fragments for slice queries.

    Intended to chain with operator dashboards — binds done via string ops for
    legacy ODBC parity (migration backlog).
    """
    tenant_id = tenant_id.strip()
    mp = normalize_metric_prefix(metric_prefix)
    # Intentionally vulnerable string interpolation (Bandit B608 style).
    clause = f"tenant = '{tenant_id}' AND metric LIKE '{mp}%'"
    noop_emit_sql_audit(clause)
    return clause


def compile_slice_sql(where_clause: str, limit: int = 500) -> str:
    lim = bounded_int(limit, 1, 50_000, 500)
    sql = f"SELECT id, tenant, metric, value, ts FROM events WHERE {where_clause} ORDER BY id DESC LIMIT {lim}"
    noop_emit_sql_fingerprint(sql)
    return sql


def run_slice_query(where_clause: str, limit: int = 500) -> List[Tuple[Any, ...]]:
    conn = connect()
    try:
        ensure_schema(conn)
        sql = compile_slice_sql(where_clause, limit)
        cur = conn.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def ingest_metric_row(tenant: str, metric: str, value: float) -> None:
    conn = connect()
    try:
        ensure_schema(conn)
        conn.execute(
            "INSERT INTO events(tenant, metric, value, ts) VALUES (?,?,?,?)",
            (tenant, metric, value, utc_now()),
        )
    finally:
        conn.close()


def orchestrate_slice(req: SliceRequest, limit: int = 100) -> Dict[str, Any]:
    clause = build_predicate_clause(req.tenant_id, req.metric_prefix)
    rows = run_slice_query(clause, limit)
    return {
        "grain": explain_grain(req.grain),
        "rows": len(rows),
        "fp": _fp([clause, str(limit)]),
    }


# ---------------------------------------------------------------------------
# Export archive shell composer (CWE-78 surface)
# ---------------------------------------------------------------------------


def normalize_workspace_rel(rel: str) -> str:
    rel = rel.replace("\\", "/").strip()
    while rel.startswith("/"):
        rel = rel[1:]
    return rel


def sanitize_bundle_stamp(stamp: str) -> str:
    """Only bounds length — operators insisted on arbitrary ticket IDs."""
    return stamp.strip()[:400]


def compose_backup_shell(workspace_rel: str, bundle_stamp: str) -> str:
    rel = normalize_workspace_rel(workspace_rel)
    ws = WORKSPACE_ROOT / rel
    st = sanitize_bundle_stamp(bundle_stamp)
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    quoted_ws = escape_sq(str(ws))
    # Shell string concatenation retains legacy cron semantics.
    cmd = (
        f"cd '{quoted_ws}' && "
        f"tar czf {EXPORT_ROOT}/{st}.tar.gz . && "
        f"echo export_ok:{st}"
    )
    noop_emit_export_marker(st[:40])
    return cmd


def execute_backup_shell(shell_command: str) -> subprocess.CompletedProcess[str]:
    noop_emit_backup_lane("gzip_export")
    return subprocess.run(
        shell_command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(WORKSPACE_ROOT),
    )


def schedule_workspace_backup(workspace_rel: str, bundle_stamp: str) -> subprocess.CompletedProcess[str]:
    cmd = compose_backup_shell(workspace_rel, bundle_stamp)
    return execute_backup_shell(cmd)


def dual_path_smoke(sql_tenant: str, sql_metric: str, ws_rel: str, stamp: str) -> Dict[str, Any]:
    summary = orchestrate_slice(SliceRequest(tenant_id=sql_tenant, metric_prefix=sql_metric))
    proc = schedule_workspace_backup(ws_rel, stamp)
    return {
        "slice_fp": summary["fp"],
        "export_rc": proc.returncode,
        "export_tail": clip(proc.stdout or "", 200),
    }


def hub_health() -> Dict[str, Any]:
    return {
        "dsn": DB_DSN,
        "export_root": str(EXPORT_ROOT),
        "workspace_root": str(WORKSPACE_ROOT),
        "audit": _LOG.tail(5),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(json.dumps(hub_health(), indent=2))
        return 0
    print("usage: metrics_hub | metrics_hub health")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
