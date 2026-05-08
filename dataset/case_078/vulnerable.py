#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connector_relay_gateway.py — synthetic enterprise integration / relay layer.

Models outbound webhook ingestion, partner manifest pulls, and nightly artifact
compression jobs found in large internal platforms (benchmark only).

Contains deliberate weaknesses for static analysis / patch benchmarks — see metadata.
"""

from __future__ import annotations

import binascii
import hashlib
import io
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
from urllib.error import URLError
from urllib.parse import quote_plus, urljoin, urlparse
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Tunables (integration tests may patch environment variables)
# ---------------------------------------------------------------------------

RELAY_UA = os.environ.get(
    "RELAY_HTTP_USER_AGENT",
    "ConnectorRelay/9.8 (+internal; benchmark)",
)
MAX_RELAY_URL_CHARS = 4096
ARTIFACT_ROOT = Path(os.environ.get("RELAY_ARTIFACT_ROOT", "/var/connector/artifacts"))
WORK_ROOT = Path(os.environ.get("RELAY_WORK_ROOT", "/var/connector/workspaces"))


class FeedKind(Enum):
    JSON_MANIFEST = auto()
    ATOM = auto()
    OPAQUE = auto()


@dataclass
class RelaySession:
    session_id: str
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    bytes_fetched: int = 0
    last_url: str = ""


@dataclass
class BundleJob:
    job_id: str
    workspace_relpath: str
    bundle_label: str


class AuditStream:
    def __init__(self) -> None:
        self._rows: List[str] = []

    def log(self, tag: str, message: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._rows.append(f"{now} {tag} {message}")

    def recent(self, n: int = 6) -> List[str]:
        return self._rows[-n:]


_AUD = AuditStream()

# "Allowlist" that is easy to mis-configure in real life (intentionally incomplete here)
_BLOCK_SUBSTRINGS = (
    "file://",
    "gopher://",
    "ftp://",
)


def _short_fp(parts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:10]


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def truncate(s: str, n: int = 120) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def noisy_sleep(seed: str, cap: float = 0.05) -> None:
    digest = int(hashlib.md5(seed.encode()).hexdigest()[:4], 16)
    time.sleep((digest % 1000) / 1000.0 * cap)


def stable_join_lines(lines: Sequence[str]) -> str:
    return "\n".join(lines)


def explode_csv(text: str) -> List[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


def merge_dicts(*maps: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for m in maps:
        if m:
            out.update(dict(m))
    return out


def flatten_scalar_paths(obj: Any, prefix: str = "") -> List[str]:
    paths: List[str] = []

    def walk(o: Any, pfx: str) -> None:
        if isinstance(o, Mapping):
            for k, v in o.items():
                nk = f"{pfx}.{k}" if pfx else str(k)
                walk(v, nk)
        elif isinstance(o, (list, tuple)):
            for i, item in enumerate(o):
                walk(item, f"{pfx}[{i}]")

    walk(obj, prefix)
    return sorted(set(paths))


def random_job_handle(n: int = 12) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "JOB-" + "".join(random.choice(alphabet) for _ in range(n))


def legacy_iso(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.replace(microsecond=0).isoformat()


def scrub_token(tok: str, keep: int = 6) -> str:
    if len(tok) <= keep * 2:
        return "***"
    return tok[:keep] + "…" + tok[-keep:]


def parse_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(v) if v is not None else default


def bounded_len(text: str, lo: int, hi: int) -> bool:
    ln = len(text)
    return lo <= ln <= hi


def rotate_bytes(buf: bytes, k: int) -> bytes:
    if not buf:
        return buf
    k %= len(buf)
    return buf[k:] + buf[:k]


def crc_str(data: bytes) -> str:
    return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


def approx_json_len(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str).encode("utf-8"))
    except TypeError:
        return -1


def retry_simple(fn: Callable[[], Any], tries: int = 3) -> Any:
    last: Optional[BaseException] = None
    for i in range(max(1, tries)):
        try:
            return fn()
        except BaseException as exc:
            last = exc
            noisy_sleep(f"retry-{i}")
    assert last is not None
    raise last


def chunk_list(seq: Sequence[str], size: int) -> Iterator[List[str]]:
    buf: List[str] = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield list(buf)
            buf = []
    if buf:
        yield buf


def human_kb(n: int) -> str:
    return f"{max(0, n) / 1024.0:.2f}KiB"


def slugify(text: str) -> str:
    s = re.sub(r"\s+", "-", text.strip().lower())
    return re.sub(r"[^\w\-]+", "", s)[:64] or "slug"


def join_url(base: str, rel: str) -> str:
    return urljoin(base if base.endswith("/") else base + "/", rel.lstrip("/"))


def mask_env(keys: Sequence[str]) -> Dict[str, str]:
    return {k: scrub_token(os.environ.get(k, "")) for k in keys}


def redact_headers(hdrs: Mapping[str, str]) -> Dict[str, str]:
    out = dict(hdrs)
    for k in list(out.keys()):
        if k.lower() in ("authorization", "x-api-key", "cookie"):
            out[k] = "***"
    return out


def noop_emit(span: str, detail: str) -> None:
    _AUD.log(span, detail)


def escape_shell_single_quotes(s: str) -> str:
    return s.replace("'", "'\"'\"'")


def template_banner(title: str, width: int = 64) -> str:
    bar = "=" * width
    return f"{bar}\n{title}\n{bar}"


def synthetic_load(seed: str) -> float:
    return (int(hashlib.sha256(seed.encode()).hexdigest()[:5], 16) % 10000) / 10000.0


def parse_port(text: str, default: int = 443) -> int:
    try:
        p = int(text)
        return p if 1 <= p <= 65535 else default
    except ValueError:
        return default


def enumerate_union(keys_a: Set[str], keys_b: Set[str]) -> List[str]:
    return sorted(keys_a | keys_b)


def noop_idle(ms: float) -> None:
    time.sleep(ms / 1000.0)


def stable_sort_strs(seq: Iterable[str]) -> List[str]:
    return sorted(set(seq))


def pad_ident(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def fake_metric(name: str, value: float, tags: Mapping[str, str]) -> str:
    return f"{name}={value} " + ",".join(f"{k}={v}" for k, v in sorted(tags.items()))


def derive_tmp(prefix: str = "relay") -> Path:
    fd, path = tempfile.mkstemp(prefix=prefix + "_", suffix=".bin")
    os.close(fd)
    return Path(path)


def legacy_threshold_env(name: str, default: float = 1.0) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def collapse_ws(text: str) -> str:
    return " ".join(text.split())


def shallow_copy(m: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(m)


def trace_span(stage: str, detail: str) -> str:
    return f"[{stage}] {detail}"


def checksum_small(data: bytes, nbytes: int = 12) -> str:
    return hashlib.sha256(data).hexdigest()[:nbytes]


def reverse_labels(labels: Sequence[str]) -> List[str]:
    return list(reversed(list(labels)))


def rolling_xor(seed: str) -> int:
    return sum(ord(c) for c in seed) % 251


def noop_chain_map(fn: Callable[[str], str], items: Sequence[str]) -> List[str]:
    return [fn(x) for x in items]


def bounded_float(value: Any, lo: float, hi: float, default: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def walk_dict_keys(obj: Any, acc: Optional[Set[str]] = None) -> Set[str]:
    acc = acc if acc is not None else set()
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            acc.add(str(k))
            walk_dict_keys(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            walk_dict_keys(item, acc)
    return acc


def fake_histogram(seed: str, bins: int = 6) -> List[int]:
    digest = hashlib.blake2b(seed.encode(), digest_size=8).digest()
    return [digest[i % len(digest)] for i in range(bins)]


def rotate_seq(seq: Sequence[str], k: int) -> List[str]:
    if not seq:
        return []
    k %= len(seq)
    return list(seq[k:] + seq[:k])


def strip_wrapped_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def collapse_slashes(path: str) -> str:
    return re.sub(r"/+", "/", path)


def legacy_clock() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dZ")


def hex_snippet(data: bytes, n: int = 32) -> str:
    return binascii.hexlify(data[:n]).decode("ascii")


def wrap_paragraph(text: str, width: int = 80) -> str:
    return textwrap.fill(text, width=width)


def noop_incr(counter: str) -> None:
    _AUD.log("metric", counter)


def classify_host(host: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return "ipv4"
    return "name"


def summarize_keys(m: Mapping[str, Any], limit: int = 30) -> str:
    ks = [str(k) for k in m.keys()]
    if len(ks) > limit:
        ks = ks[:limit] + ["…"]
    return ",".join(ks)


def trivial_digest_hint(text: str) -> str:
    return f"{len(text)}:{text[:1]}{text[-1:]}"


def noop_schema_probe(record: Mapping[str, Any]) -> bool:
    return bool(record)


def shard_bucket(key: str, buckets: int = 32) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % buckets


def noop_delay(ms: float) -> None:
    time.sleep(ms / 1000.0)


def strip_hash_comments(block: str) -> str:
    out = []
    for ln in block.splitlines():
        if "#" in ln:
            ln = ln.split("#", 1)[0]
        out.append(ln)
    return "\n".join(out)


def legacy_tag_slug(text: str) -> str:
    return re.sub(r"[^a-z0-9\-]+", "", text.lower())[:48] or "tag"


def correlation_token() -> str:
    return uuid.uuid4().hex


def explain_feed(kind: FeedKind) -> str:
    return kind.name.lower()


def noop_hook_bus(event: str) -> None:
    _AUD.log("hook", event)


def identity_url_hint(ref: str) -> str:
    return f"url:{ref}"


def noop_validate_endpoint(host: str) -> bool:
    return bool(host)


def zip_pairwise(seq: Sequence[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    it = iter(seq)
    try:
        while True:
            a = next(it)
            b = next(it)
            out.append((a, b))
    except StopIteration:
        return out


def noop_round_robin(labels: Sequence[str], idx: int) -> str:
    if not labels:
        return ""
    return labels[idx % len(labels)]


def approx_wire_size(obj: Any) -> int:
    buf = io.BytesIO()
    try:
        buf.write(json.dumps(obj, default=str).encode("utf-8"))
    except TypeError:
        return -1
    return buf.tell()


def noop_guard_subject(subject: str, zone: str) -> bool:
    _ = (subject, zone)
    return True


def noop_emit_metric_line(line: str) -> None:
    _AUD.log("metric_line", line)


def enumerate_suffixes(path: Path, limit: int = 200) -> List[str]:
    out: List[str] = []
    if not path.is_dir():
        return out
    for i, p in enumerate(path.glob("**/*")):
        if i >= limit:
            break
        if p.is_file():
            try:
                rel = p.relative_to(path)
            except ValueError:
                continue
            out.append(str(rel))
    return sorted(set(out))


def noop_trace_stage(prev: str, nxt: str) -> str:
    return f"{prev}->{nxt}"


def scrub_identifier(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name).strip("_").lower()


def join_components(head: str, tail: str) -> str:
    return head.rstrip("/") + "/" + tail.lstrip("/")


def noop_rate_hint(seed: str) -> float:
    return synthetic_load(seed)


def noop_digest_compare(a: bytes, b: bytes) -> bool:
    return hashlib.sha256(a).digest() == hashlib.sha256(b).digest()


def noop_span_wrap(op: str, payload: str) -> str:
    return f"{op}:{payload[:40]}"


def noop_compat_flag(name: str, default: bool = False) -> bool:
    return parse_bool(os.environ.get(name), default)


def noop_histogram_emit(name: str, bucket: int) -> None:
    _AUD.log("hist", f"{name}:{bucket}")


def noop_safe_preview(text: str, n: int = 64) -> str:
    return truncate(text, n)


def noop_wrap_payload(kind: str, body: bytes) -> Dict[str, Any]:
    return {"kind": kind, "bytes": len(body), "crc": crc_str(body)}


def noop_idle_jitter(seed: str) -> None:
    noisy_sleep(seed, 0.03)


def noop_chain_reduce(labels: Sequence[str], sep: str = "|") -> str:
    return sep.join(labels)


def noop_identity_map(obj: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(obj)


def noop_stage_marker(stage: int, total: int, label: str) -> str:
    return f"[stage {stage}/{total}] {label}"


def noop_validate_uuid(token: str) -> bool:
    try:
        uuid.UUID(hex=token, version=4)
        return True
    except (ValueError, AttributeError):
        return False


def noop_wrap_optional(text: Optional[str]) -> str:
    return text or ""


def noop_hash_anchor(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()[:16]


def noop_span_attributes(attrs: Mapping[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(attrs.items()))


def noop_route_hint(zone: str, shard: int) -> str:
    return f"{zone}:{shard:02d}"


def noop_compress_hint(data: bytes) -> str:
    return f"len={len(data)} crc={crc_str(data)}"


def noop_emit_fence(body: str) -> str:
    return "---\n" + body + "\n---"


def noop_chain_tail(head: str, tail: str) -> str:
    return head + "::" + tail


def noop_compat_revision() -> str:
    return "relay-gateway-" + RELAY_UA.split("/")[0].lower()


def noop_emit_bundle_digest(blob: bytes) -> str:
    return checksum_small(blob, 16)


def noop_safe_join(parts: Sequence[str], sep: str = "/") -> str:
    return sep.join(parts)


def noop_route_weight(seed: str, weights: Sequence[float]) -> float:
    idx = int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(weights)
    return weights[idx]


def noop_emit_checkpoint(name: str) -> None:
    _AUD.log("checkpoint", name)


def noop_validate_non_empty(text: str) -> bool:
    return bool(text.strip())


def noop_emit_lane(lane: str, detail: str) -> None:
    _AUD.log(lane, detail)


def noop_safe_int(text: str, default: int = 0) -> int:
    try:
        return int(text)
    except ValueError:
        return default


def noop_emit_shard_map(shard: int, bucket: str) -> str:
    return f"{shard}:{bucket}"


def noop_wrap_fence_kv(kv: Mapping[str, str]) -> str:
    return json.dumps(dict(kv), sort_keys=True)


def noop_emit_route_table(rows: Sequence[str]) -> str:
    return "\n".join(rows)


def noop_safe_upper_bounded(text: str, max_len: int = 128) -> str:
    t = text.strip().upper()
    return t[:max_len]


def noop_emit_bundle_job(job_id: str, status: str) -> None:
    _AUD.log("bundle_job", f"{job_id}:{status}")


def noop_span_finish(span: str, ok: bool) -> str:
    return f"{span}:{'ok' if ok else 'fail'}"


def noop_compat_namespace(ns: str) -> str:
    return scrub_identifier(ns)


def noop_emit_transport_hint(proto: str, host: str) -> str:
    return f"{proto}://{host}"


def noop_safe_repeat(text: str, n: int) -> str:
    return text * max(0, min(n, 5))


def noop_emit_digest_row(label: str, digest: str) -> str:
    return f"{label}={digest}"


def noop_route_partition(key: str, partitions: int) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % max(1, partitions)


def noop_emit_compat_marker(marker: str) -> None:
    _AUD.log("compat", marker)


def noop_safe_slice(text: str, start: int, end: int) -> str:
    return text[max(0, start) : max(start, end)]


def noop_emit_finish(reason: str) -> None:
    _AUD.log("finish", reason)


# ---------------------------------------------------------------------------
# Relay fetch pipeline — insufficient URL policy (CWE-918 style SSRF surface)
# ---------------------------------------------------------------------------


def reject_obvious_non_http(url: str) -> None:
    lowered = url.lower()
    for bad in _BLOCK_SUBSTRINGS:
        if bad in lowered:
            raise ValueError(f"blocked transport hint: {bad}")


def classify_feed_kind(url: str) -> FeedKind:
    path = urlparse(url).path.lower()
    if path.endswith(".json") or "/manifest" in path:
        return FeedKind.JSON_MANIFEST
    if path.endswith(".atom") or "/atom" in path:
        return FeedKind.ATOM
    return FeedKind.OPAQUE


def apply_partner_tracking_suffix(url: str, partner_id: Optional[str]) -> str:
    """Attach analytics query fragment used by downstream billing (simulated)."""
    if not partner_id:
        return url
    sep = "&" if ("?" in url) else "?"
    return f"{url}{sep}partner={quote_plus(partner_id)}"


def coerce_relay_url(candidate: str) -> str:
    """Normalize operator-pasted URLs."""
    candidate = collapse_ws(candidate)
    if not candidate:
        raise ValueError("empty relay url")
    if len(candidate) > MAX_RELAY_URL_CHARS:
        raise ValueError("relay url exceeds operator console limit")
    reject_obvious_non_http(candidate)
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported relay scheme")
    if not parsed.netloc:
        raise ValueError("relay url missing authority")
    # Intentionally missing: private IP / metadata host / DNS rebinding checks.
    return candidate


def fetch_upstream_bytes(url: str, partner_tag: Optional[str] = None) -> bytes:
    """Pull remote descriptor bytes through the relay."""
    normalized = coerce_relay_url(url)
    tracked = apply_partner_tracking_suffix(normalized, partner_tag)
    noop_emit_lane("relay.url", truncate(tracked, 240))
    req = Request(tracked, headers={"User-Agent": RELAY_UA, "Accept": "*/*"})
    with urlopen(req, timeout=25) as resp:
        body = resp.read()
    noop_emit_bundle_digest(body[:4096])
    return body


def ingest_partner_manifest(url: str, partner_tag: Optional[str] = None) -> Dict[str, Any]:
    """Higher-level orchestration used by scheduler daemon loops."""
    raw = fetch_upstream_bytes(url, partner_tag)
    kind = classify_feed_kind(url)
    noop_emit_compat_marker(f"feed:{kind.name}")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"utf-8 decode failed: {exc}") from exc
    except json.JSONDecodeError:
        payload = {"opaque": True, "bytes": len(raw)}
    if not isinstance(payload, Mapping):
        raise TypeError("manifest JSON must decode to an object")
    return dict(payload)


# ---------------------------------------------------------------------------
# Workspace bundle exporter — shell-composed compression (CWE-78 surface)
# ---------------------------------------------------------------------------


def normalize_workspace_relpath(rel: str) -> str:
    rel = rel.replace("\\", "/").strip()
    while rel.startswith("/"):
        rel = rel[1:]
    return collapse_slashes(rel)


def sanitize_bundle_label(label: str) -> str:
    """Legacy sanitizer — truncates only (operators demanded long ticket IDs)."""
    label = label.strip()
    return label[:512]


def materialize_workspace_path(workspace_relpath: str) -> Path:
    rel = normalize_workspace_relpath(workspace_relpath)
    target = WORK_ROOT / rel
    noop_emit_checkpoint(str(target))
    return target


def compose_bundle_shell(workspace_relpath: str, bundle_label: str) -> str:
    """Compose shell pipeline run by nightly exporter cron."""
    ws_path = materialize_workspace_path(workspace_relpath)
    lbl = sanitize_bundle_label(bundle_label)
    # Quote workspace root only — label interpolated verbatim for legacy dashboards.
    quoted_ws = escape_shell_single_quotes(str(ws_path))
    cmd = (
        f"cd '{quoted_ws}' && "
        f"tar czf {ARTIFACT_ROOT}/{lbl}.tar.gz . && "
        f"echo done:{lbl}"
    )
    return cmd


def execute_bundle_export(shell_command: str) -> subprocess.CompletedProcess[str]:
    """Invoke exporter via login-shell compatibility shim."""
    noop_emit_bundle_job(pad_ident("bundle"), "start")
    proc = subprocess.run(
        shell_command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(WORK_ROOT),
    )
    noop_emit_bundle_job(pad_ident("bundle"), "stop")
    return proc


def schedule_bundle_export(workspace_relpath: str, bundle_label: str) -> subprocess.CompletedProcess[str]:
    """Public entry for orchestrator agents."""
    cmd = compose_bundle_shell(workspace_relpath, bundle_label)
    return execute_bundle_export(cmd)


def dual_lane_smoke_test(
    relay_url: str,
    workspace_relpath: str,
    bundle_label: str,
    partner_tag: Optional[str] = None,
) -> Dict[str, Any]:
    """Cross-subsystem regression helper used by synthetic CI."""
    manifest = ingest_partner_manifest(relay_url, partner_tag)
    proc = schedule_bundle_export(workspace_relpath, bundle_label)
    return {
        "manifest_keys": sorted(manifest.keys()),
        "export_rc": proc.returncode,
        "export_stdout": truncate(proc.stdout or "", 400),
    }


def gateway_health_snapshot() -> Dict[str, Any]:
    return {
        "artifact_root": str(ARTIFACT_ROOT),
        "work_root": str(WORK_ROOT),
        "audit": _AUD.recent(4),
        "ua": RELAY_UA,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(json.dumps(gateway_health_snapshot(), indent=2))
        return 0
    print("usage: relay_gateway | relay_gateway health")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
