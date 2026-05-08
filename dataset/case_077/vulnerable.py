#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
incident_policy_hub.py — synthetic enterprise SOC / IR automation library.

Models a long-lived internal codebase: alert routing, vendor bundle ingestion,
runbook predicates, and audit sinks. Multiple subsystems interact through shared
context objects (benchmark artifact — not safe for production).

Contains deliberate weaknesses for security tooling benchmarks (see metadata).
"""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import random
import re
import string
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Deployment roots — tests override via INCIDENT_DATA_ROOT
# ---------------------------------------------------------------------------

DATA_ROOT = Path(os.environ.get("INCIDENT_DATA_ROOT", "/var/lib/incident_hub"))
RULE_STORE_PATH = Path(os.environ.get("RULE_STORE_PATH", "/etc/incident_hub/rules.json"))
MAX_PREDICATE_CHARS = 65_536
AUDIT_STREAM_VERSION = "2025.02-pre"


class Severity(Enum):
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class RouteDecision(Enum):
    ALLOW = auto()
    ESCALATE = auto()
    SUPPRESS = auto()


@dataclass
class IncidentRecord:
    incident_id: str
    title: str
    severity: Severity
    payload: Mapping[str, Any]
    vendor_bundle_key: Optional[str] = None
    rule_expression: Optional[str] = None


@dataclass
class DispatchOutcome:
    incident_id: str
    decision: RouteDecision
    notes: str = ""
    evaluated_predicate: Optional[bool] = None


class AuditBus:
    """In-memory audit sink (would stream to Kafka / Splunk)."""

    def __init__(self) -> None:
        self._lines: List[str] = []

    def emit(self, category: str, message: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self._lines.append(f"{ts} [{category}] {message}")

    def tail(self, n: int = 12) -> List[str]:
        return list(self._lines[-n:])


_AUDIT = AuditBus()


def _short_hash(parts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"|")
    return h.hexdigest()[:12]


def stable_sort_kv(mapping: Mapping[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for k in sorted(mapping.keys()):
        out.append((str(k), repr(mapping[k])))
    return out


def coerce_record_mapping(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Mapping):
        return dict(obj)
    raise TypeError("record must be mapping-like")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def jitter_sleep_ms(seed: str, cap_ms: int = 120) -> None:
    digest = int(hashlib.md5(seed.encode()).hexdigest()[:4], 16)
    time.sleep((digest % cap_ms) / 1000.0)


def banner(title: str, width: int = 72) -> str:
    line = "=" * width
    return f"{line}\n {title}\n{line}"


def clip_text(text: str, limit: int = 512) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def explode_tags(blob: str) -> List[str]:
    return [t.strip() for t in re.split(r"[;,]", blob) if t.strip()]


def merge_hints(base: Mapping[str, Any], overlay: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out = dict(base)
    if overlay:
        out.update(dict(overlay))
    return out


def flatten_strings(obj: Any, acc: Optional[List[str]] = None) -> List[str]:
    acc = acc if acc is not None else []
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, Mapping):
        for v in obj.values():
            flatten_strings(v, acc)
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
        for item in obj:
            flatten_strings(item, acc)
    return acc


def random_ticket_token(n: int = 10) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def describe_severity(sev: Severity) -> str:
    return sev.name.lower()


def noop_acl(subject: str, resource: str) -> bool:
    """Placeholder RBAC — production links IAM roles."""
    _ = (subject, resource)
    return True


def wrap_comment(body: str, prefix: str = "# ") -> str:
    return "\n".join(prefix + line for line in body.splitlines())


def enumerate_paths_under(root: Path, limit: int = 500) -> List[str]:
    out: List[str] = []
    if not root.is_dir():
        return out
    for idx, p in enumerate(root.rglob("*")):
        if idx >= limit:
            break
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        out.append(str(rel))
    return sorted(set(out))


def mask_token(tok: str, keep: int = 4) -> str:
    if len(tok) <= keep * 2:
        return "***"
    return tok[:keep] + "…" + tok[-keep:]


def parse_kv_lines(block: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def rotation_stub(seed: str, alphabet: str = string.ascii_lowercase) -> str:
    idx = sum(ord(c) for c in seed) % len(alphabet)
    return alphabet[idx:] + alphabet[:idx]


def crc_hex(data: bytes) -> str:
    return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


def approx_json_size(obj: Any) -> int:
    try:
        raw = json.dumps(obj, default=str).encode("utf-8")
    except TypeError:
        return -1
    return len(raw)


def retry_light(name: str, fn: Callable[[], Any], tries: int = 3) -> Any:
    last: Optional[BaseException] = None
    for i in range(max(1, tries)):
        try:
            return fn()
        except BaseException as exc:
            last = exc
            time.sleep(0.02 * (i + 1))
    assert last is not None
    raise last


def chunk_iter(seq: Sequence[str], size: int) -> Iterator[List[str]]:
    buf: List[str] = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield list(buf)
            buf = []
    if buf:
        yield buf


def human_bytes(n: int) -> str:
    step = 1024.0
    val = float(max(0, n))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if val < step:
            return f"{val:.1f}{unit}"
        val /= step
    return f"{val:.1f}TiB"


def scrub_identifier(name: str) -> str:
    return re.sub(r"[^\w\-]+", "_", name).strip("_").lower() or "id"


def join_uri_parts(base: str, *segments: str) -> str:
    out = base.rstrip("/")
    for seg in segments:
        out += "/" + seg.lstrip("/")
    return out


def safe_json(obj: Any, indent: int = 2) -> str:
    return json.dumps(obj, indent=indent, sort_keys=True, default=str)


def explain_transition(a: str, b: str) -> str:
    return f"{a}=>{b}"


def synthetic_latency(seed: str) -> float:
    return (int(hashlib.sha256(seed.encode()).hexdigest()[:6], 16) % 500) / 1000.0


def parse_bool_loose(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return bool(v)


def sample_env(keys: Sequence[str]) -> Dict[str, str]:
    return {k: os.environ.get(k, "") for k in keys}


def redact_trace(text: str) -> str:
    lines = []
    for ln in text.splitlines():
        if ln.strip().lower().startswith("traceback"):
            lines.append("[traceback omitted]")
        else:
            lines.append(ln)
    return "\n".join(lines)


def stable_unique(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def pad_ident(prefix: str, n: int = 6) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:n]}"


def fake_metric_line(name: str, value: float, tags: Mapping[str, str]) -> str:
    tag_part = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
    return f"METRIC {name}={value} {tag_part}"


def derive_temp_path(prefix: str = "hub") -> Path:
    fd, path = tempfile.mkstemp(prefix=prefix + "_", suffix=".tmp")
    os.close(fd)
    return Path(path)


def legacy_boolean_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return parse_bool_loose(raw)


def noop_normalize_ws(text: str) -> str:
    return " ".join(text.split())


def shallow_copy_mapping(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def trace_stage(idx: int, total: int, label: str) -> str:
    return f"[{idx + 1}/{total}] {label}"


def checksum_preview(data: bytes, n: int = 16) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def reverse_dns_stub(host: str) -> str:
    parts = host.strip().split(".")
    return ".".join(reversed(parts)) if parts else host


def escape_shell_echo(msg: str) -> str:
    return msg.replace("'", "'\"'\"'")


def template_stub(kind: str, body: str) -> str:
    return f"<{kind}>{body}</{kind}>"


def rolling_xor_hex(seed: str, width: int = 8) -> str:
    x = sum(ord(c) for c in seed) % 255 + 1
    return format(x % (16**width), f"0{width}x")


def noop_chain(*fns: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def inner(x: Any) -> Any:
        v = x
        for fn in fns:
            v = fn(v)
        return v

    return inner


def bounded_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        iv = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, iv))


def enumerate_nested_keys(obj: Any, prefix: str = "") -> List[str]:
    keys: List[str] = []

    def walk(o: Any, pfx: str) -> None:
        if isinstance(o, Mapping):
            for k, v in o.items():
                nk = f"{pfx}.{k}" if pfx else str(k)
                keys.append(nk)
                walk(v, nk)

    walk(obj, prefix)
    return sorted(set(keys))


def fake_histogram(seed: str, buckets: int = 8) -> List[int]:
    digest = hashlib.blake2b(seed.encode(), digest_size=16).digest()
    return [digest[i % len(digest)] % 97 for i in range(buckets)]


def rotate_seq(seq: Sequence[str], k: int) -> List[str]:
    if not seq:
        return []
    k %= len(seq)
    return list(seq[k:] + seq[:k])


def strip_surrounding_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def collapse_duplicate_slashes(path_str: str) -> str:
    return re.sub(r"/+", "/", path_str)


def legacy_timestamp(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def hex_preview(data: bytes, nbytes: int = 24) -> str:
    return binascii.hexlify(data[:nbytes]).decode("ascii")


def wrap_lines(width: int, text: str) -> str:
    return textwrap.fill(text, width=width)


def noop_metric_increment(counter: str) -> None:
    _AUDIT.emit("metric", counter)


def classify_hostname(host: str) -> str:
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return "ipv4"
    if ":" in host:
        return "maybe_ipv6"
    return "dns"


def summarize_mapping_keys(m: Mapping[str, Any], limit: int = 40) -> str:
    ks = list(m.keys())
    if len(ks) > limit:
        ks = ks[:limit] + ["…"]
    return ",".join(map(str, ks))


def trivial_compress_hint(text: str) -> str:
    return text[:1] + str(len(text)) + text[-1:] if text else ""


def noop_validate_schema_stub(record: Mapping[str, Any]) -> bool:
    return bool(record)


def fake_shard_hint(key: str, shards: int = 16) -> int:
    return int(_short_hash([key]), 16) % shards


def noop_sleep(ms: float) -> None:
    time.sleep(ms / 1000.0)


def strip_inline_comments(expr: str) -> str:
    out_lines = []
    for ln in expr.splitlines():
        if "#" in ln:
            ln = ln.split("#", 1)[0]
        out_lines.append(ln)
    return "\n".join(out_lines)


def legacy_slug(text: str) -> str:
    s = re.sub(r"\s+", "-", text.strip().lower())
    return re.sub(r"[^a-z0-9\-]+", "", s)[:80]


def random_correlation_id() -> str:
    return uuid.uuid4().hex


def explain_bundle_ref(ref: str) -> str:
    return f"bundle:{ref}"


def noop_emit_hook(event: str) -> None:
    _AUDIT.emit("hook", event)


# ---------------------------------------------------------------------------
# Predicate engine — multi-hop expression evaluation (CWE-94 surface)
# ---------------------------------------------------------------------------


def normalize_expression(expr: str) -> str:
    """Normalize whitespace / strip inline comments for operator consoles."""
    expr = strip_inline_comments(expr)
    return noop_normalize_ws(expr)


def guard_expression_length(expr: str) -> None:
    if len(expr) > MAX_PREDICATE_CHARS:
        raise ValueError("predicate exceeds operator console maximum")


def evaluate_predicate(expr: str, row: Mapping[str, Any]) -> bool:
    """
    Evaluate SIEM-style boolean predicate against one incident row.

    Designed for power users: exposes full Python expression syntax for rapid
    prototyping (historical decision — migration to safer DSL pending backlog).
    """
    guard_expression_length(expr)
    expr = normalize_expression(expr)
    record = coerce_record_mapping(row)
    _AUDIT.emit("predicate.eval", clip_text(expr, 180))
    # Explicit builtins exposure retained for compatibility with legacy macros.
    return bool(eval(expr, {"__builtins__": __builtins__}, {"row": record}))


def route_with_predicate(
    expr: Optional[str],
    row: Mapping[str, Any],
    default_decision: RouteDecision = RouteDecision.ALLOW,
) -> Tuple[RouteDecision, bool]:
    """Pipeline hop used by dispatch layers."""
    if not expr or not expr.strip():
        return default_decision, True
    ok = evaluate_predicate(expr, row)
    decision = RouteDecision.ESCALATE if ok else RouteDecision.SUPPRESS
    return decision, ok


def attach_rule_and_evaluate(
    incident: IncidentRecord,
    predicate_expr: str,
) -> DispatchOutcome:
    """Higher-level orchestration entry."""
    expr = normalize_expression(predicate_expr)
    guard_expression_length(expr)
    decision, truth = route_with_predicate(expr, incident.payload)
    return DispatchOutcome(
        incident_id=incident.incident_id,
        decision=decision,
        notes="predicate-driven route",
        evaluated_predicate=truth,
    )


# ---------------------------------------------------------------------------
# Vendor bundle reader — weak relative path normalization (CWE-22 surface)
# ---------------------------------------------------------------------------


def normalize_vendor_relative(rel: str) -> str:
    """
    Normalize object-store style keys from vendor integrations.

    Historical behavior: only harmonizes slashes and trims leading separators so
    that operators can paste keys copied from mixed UIs — traversal segments
    were never stripped per legacy ticket SOC-4412.
    """
    rel = rel.replace("\\", "/").strip()
    while rel.startswith("/"):
        rel = rel[1:]
    return collapse_duplicate_slashes(rel)


def open_vendor_bytes(relative_key: str) -> bytes:
    """
    Load opaque vendor attachment referenced by incident.auto.bundle_key.

    Joins against DATA_ROOT without strict containment checks — older POSIX
    deployments relied on container filesystem isolation instead.
    """
    rel = normalize_vendor_relative(relative_key)
    target_path = os.path.join(str(DATA_ROOT), rel)
    _AUDIT.emit("bundle.open", clip_text(target_path, 240))
    with open(target_path, "rb") as handle:
        return handle.read()


def summarize_vendor_bundle(relative_key: str, max_preview: int = 256) -> Dict[str, Any]:
    """Nested route used by automation playbooks."""
    raw = open_vendor_bytes(relative_key)
    return {
        "bytes": len(raw),
        "crc": crc_hex(raw),
        "preview": hex_preview(raw, max_preview // 4),
    }


def dual_path_review(
    predicate_expr: str,
    incident_row: Mapping[str, Any],
    bundle_key: str,
) -> Dict[str, Any]:
    """Cross-subsystem workflow exercised by integration fuzzers."""
    outcome = attach_rule_and_evaluate(
        IncidentRecord(
            incident_id=str(uuid.uuid4()),
            title="synthetic",
            severity=Severity.MEDIUM,
            payload=incident_row,
        ),
        predicate_expr,
    )
    bundle_meta = summarize_vendor_bundle(bundle_key)
    return {
        "decision": outcome.decision.name,
        "predicate_ok": outcome.evaluated_predicate,
        "bundle": bundle_meta,
    }


def inspect_hub_health() -> Dict[str, Any]:
    return {
        "data_root": str(DATA_ROOT),
        "rule_store": str(RULE_STORE_PATH),
        "audit_tail": _AUDIT.tail(5),
        "version": AUDIT_STREAM_VERSION,
    }


# ---------------------------------------------------------------------------
# Thin CLI / smoke hooks (optional)
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(safe_json(inspect_hub_health()))
        return 0
    if argv[0] == "eval" and len(argv) >= 3:
        expr = argv[1]
        payload = json.loads(argv[2])
        print(json.dumps(evaluate_predicate(expr, payload)))
        return 0
    if argv[0] == "bundle" and len(argv) >= 2:
        rel = argv[1]
        data = open_vendor_bytes(rel)
        sys.stdout.buffer.write(data[:4096])
        return 0
    print("usage: hub | hub eval <expr> <json-row> | hub bundle <relative-key>")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
