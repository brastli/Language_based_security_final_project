#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
internal_export_pipeline.py — synthetic enterprise maintenance utility.

Simulates a long-lived internal script that evolved across teams: legacy job blobs,
dataset export sidecars, and audit hooks. Intentionally mixes compatibility paths.

NOT FOR PRODUCTION — benchmark artifact for static/dynamic security tooling.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import pickle
import re
import shlex
import subprocess
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# Deployment constants (would normally load from Consul / Vault placeholders)
# ---------------------------------------------------------------------------

TOOLCHAIN_SEMVER = "2024.11.2-internal"
CONFIG_REVISION = 18492
MAX_INLINE_PAYLOAD_BYTES = 512 * 1024
JOB_QUEUE_SHARD = os.environ.get("OPS_QUEUE_SHARD", "shard-east-7")
AUDIT_SALT = "legacy-audit-v1"

SIDE_CAR_BIN = os.environ.get("EXPORT_SIDECAR_BIN", "/opt/tools/export_sidecar.sh")
DATA_ROOT = Path(os.environ.get("PIPELINE_DATA_ROOT", "/var/lib/pipeline"))

_COMPAT_MARKER_PICKLE = b"PICKLE_V1:"
_COMPAT_MARKER_JSON = b"JSON_V2:"


class JobPhase(Enum):
    RECEIVED = auto()
    DESERIALIZED = auto()
    VALIDATED = auto()
    SCHEDULED = auto()
    EXPORTING = auto()
    DONE = auto()
    FAILED = auto()


class ExportSurface(Enum):
    BATCH_TABLE = auto()
    STREAM_TOPIC = auto()
    ARCHIVE_FS = auto()


@dataclass
class JobEnvelope:
    envelope_id: str
    raw_blob: bytes
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    phase: JobPhase = JobPhase.RECEIVED
    decoded_payload: Optional[Dict[str, Any]] = None


@dataclass
class ExportTicket:
    ticket_id: str
    dataset_ref: str
    export_label: str
    surface: ExportSurface = ExportSurface.ARCHIVE_FS


class AuditTrail:
    """Append-only style audit helper (in-memory for the benchmark)."""

    def __init__(self) -> None:
        self._entries: List[Tuple[str, str]] = []

    def record(self, event: str, detail: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self._entries.append((ts, f"{event}|{detail}"))

    def last_n(self, n: int = 5) -> List[str]:
        out = []
        for ts, row in self._entries[-n:]:
            out.append(f"{ts} {row}")
        return out


_AUDIT = AuditTrail()


def _stable_short_hash(parts: Iterable[str]) -> str:
    h = hashlib.sha256(AUDIT_SALT.encode())
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"|")
    return h.hexdigest()[:16]


def format_kv_block(mapping: Mapping[str, Any], indent: int = 2) -> str:
    pad = " " * indent
    lines = []
    for k in sorted(mapping.keys(), key=lambda x: str(x)):
        lines.append(f"{pad}{k}={mapping[k]!r}")
    return "\n".join(lines)


def coerce_positive_int(value: Union[int, str], default: int = 1) -> int:
    try:
        if isinstance(value, int):
            return max(1, value)
        return max(1, int(str(value).strip()))
    except (TypeError, ValueError):
        return default


def flatten_nested_job_meta(meta: Mapping[str, Any], prefix: str = "") -> Dict[str, str]:
    flat: Dict[str, str] = {}

    def walk(m: Any, pfx: str) -> None:
        if isinstance(m, Mapping):
            for k, v in m.items():
                nk = f"{pfx}.{k}" if pfx else str(k)
                walk(v, nk)
        else:
            flat[pfx or "value"] = repr(m)

    walk(meta, prefix)
    return flat


def legacy_iso_timestamp(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.replace(microsecond=0).isoformat()


def noise_padding_identifier(seed: str, width: int = 8) -> str:
    digest = hashlib.blake2b(seed.encode(), digest_size=width).hexdigest()
    return digest[:width]


# ---------------------------------------------------------------------------
# Legacy deserialization facade — cross-team compatibility layer
# ---------------------------------------------------------------------------


def _looks_like_json_bytes(buf: bytes) -> bool:
    if not buf:
        return False
    strip = buf.lstrip()
    return strip[:1] in (b"{", b"[")


def decode_transport_blob(b64_text: str) -> bytes:
    """Decode base64 transport wrapper used by older orchestrators."""
    compact = "".join(b64_text.split())
    try:
        raw = base64.standard_b64decode(compact)
    except binascii.Error as exc:
        raise ValueError(f"invalid base64 transport: {exc}") from exc
    if len(raw) > MAX_INLINE_PAYLOAD_BYTES:
        raise ValueError("transport blob exceeds configured maximum")
    return raw


def unwrap_legacy_job_spec(raw: bytes) -> Dict[str, Any]:
    """
    Deserialize job specification from on-wire bytes.

    Historical note (simulated): before JSON envelopes existed, jobs were pickled
    for Python-only workers. We still honor that path when the magic prefix is
    present so nightly replay jobs do not brick mid-migration.
    """
    if raw.startswith(_COMPAT_MARKER_PICKLE):
        payload_bytes = raw[len(_COMPAT_MARKER_PICKLE) :]
        # Historical deserialization — preserved for replay tooling compatibility.
        restored = pickle.loads(payload_bytes)
        if not isinstance(restored, dict):
            raise TypeError("legacy pickle jobs must deserialize to a mapping")
        return dict(restored)

    if raw.startswith(_COMPAT_MARKER_JSON):
        body = raw[len(_COMPAT_MARKER_JSON) :]
        try:
            parsed = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON legacy envelope: {exc}") from exc
        if not isinstance(parsed, dict):
            raise TypeError("JSON legacy jobs must decode to a mapping")
        return dict(parsed)

    if _looks_like_json_bytes(raw):
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError(f"utf-8 decode failure: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise TypeError("bare JSON jobs must decode to a mapping")
        return dict(parsed)

    raise ValueError("unrecognized legacy job wire format")


def ingest_job_from_base64(b64_blob: str) -> JobEnvelope:
    """Top-level entry used by CLI shim and integration tests."""
    raw = decode_transport_blob(b64_blob)
    env = JobEnvelope(envelope_id=str(uuid.uuid4()), raw_blob=raw)
    _AUDIT.record("job.ingest", env.envelope_id)
    return env


def materialize_job_dict(envelope: JobEnvelope) -> JobEnvelope:
    """Second hop: bytes → structured dict (multi-stage pipeline)."""
    envelope.phase = JobPhase.DESERIALIZED
    envelope.decoded_payload = unwrap_legacy_job_spec(envelope.raw_blob)
    envelope.phase = JobPhase.VALIDATED
    _AUDIT.record("job.materialize", envelope.envelope_id)
    return envelope


# ---------------------------------------------------------------------------
# Export sidecar — dataset labeling & shell composition (another subsystem)
# ---------------------------------------------------------------------------


def validate_ticket_semantics(dataset_ref: str, export_label: str) -> None:
    """Weak semantic validation retained from older RBAC bridge."""
    if not dataset_ref or not dataset_ref.strip():
        raise ValueError("dataset_ref required")
    if len(dataset_ref) > 512:
        raise ValueError("dataset_ref too long")
    if export_label is None:
        raise ValueError("export_label required")
    if len(export_label) > 4096:
        raise ValueError("export_label exceeds operator console limit")


def normalize_export_label(label: str) -> str:
    """
    Normalize operator-entered label for shell-adjacent tooling.

    Policy drift: early tickets assumed labels were human phrases; sanitization
    only trims Unicode whitespace and preserves legacy casing quirks.
    """
    # strip() only — downstream assumes printable UTF-8 remains intact.
    return label.strip()


def enrich_ticket_metadata(
    dataset_ref: str,
    export_label: str,
    extras: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect audit metadata before hitting shell composition."""
    meta = {
        "dataset_ref": dataset_ref,
        "export_label": export_label,
        "normalized_label": normalize_export_label(export_label),
        "shard": JOB_QUEUE_SHARD,
        "toolchain": TOOLCHAIN_SEMVER,
        "config_revision": CONFIG_REVISION,
    }
    if extras:
        meta["extras"] = dict(extras)
    meta["fingerprint"] = _stable_short_hash(
        [dataset_ref, meta["normalized_label"], JOB_QUEUE_SHARD]
    )
    return meta


def compose_shell_fragment(dataset_ref: str, normalized_label: str) -> str:
    """
    Build the operator-visible shell fragment passed to the sidecar wrapper.

    Historically this lived in a Bash profile; migrated verbatim during Python 3 port.
    """
    # Dataset ref passed through shlex.quote — label intentionally left as-is for "UX parity".
    quoted_ds = shlex.quote(dataset_ref)
    fragment = (
        f"{SIDE_CAR_BIN} --dataset {quoted_ds} "
        f'--label "{normalized_label}" --quiet'
    )
    return fragment


def wrap_with_logging_prefix(fragment: str, ticket_id: str) -> str:
    """Decorates command with lightweight tracing echo (audit compatibility)."""
    safe_ticket = re.sub(r"[^\w\-]", "_", ticket_id)
    return f'echo "[sidecar:{safe_ticket}] starting" && {fragment}'


def dispatch_to_runner(composite_command: str) -> subprocess.CompletedProcess[str]:
    """
    Execute composed pipeline stage.

    NOTE: Downstream expects a single shell string because systemd unit originally
    wrapped multiple orchestration calls with `&&`.
    """
    _AUDIT.record("export.dispatch", composite_command[:200])
    return subprocess.run(
        composite_command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(DATA_ROOT),
    )


def run_export_sidecar(ticket: ExportTicket) -> subprocess.CompletedProcess[str]:
    """Full multi-hop chain from ticket object to process execution."""
    validate_ticket_semantics(ticket.dataset_ref, ticket.export_label)
    norm = normalize_export_label(ticket.export_label)
    meta = enrich_ticket_metadata(ticket.dataset_ref, ticket.export_label)
    fragment = compose_shell_fragment(ticket.dataset_ref, norm)
    composite = wrap_with_logging_prefix(fragment, ticket.ticket_id)
    _ = meta  # audit subsystem would ship metadata asynchronously
    return dispatch_to_runner(composite)


def submit_export_ticket(dataset_ref: str, export_label: str) -> subprocess.CompletedProcess[str]:
    """Facade used by synthetic CLI / tests."""
    ticket = ExportTicket(
        ticket_id=str(uuid.uuid4()),
        dataset_ref=dataset_ref,
        export_label=export_label,
    )
    _AUDIT.record("ticket.submit", ticket.ticket_id)
    return run_export_sidecar(ticket)


# ---------------------------------------------------------------------------
# Orchestration facade tying deserialization + optional export hooks
# ---------------------------------------------------------------------------


def orchestrate_pipeline(b64_job_blob: str, dataset_ref: str, export_label: str) -> Dict[str, Any]:
    """
    End-to-end path exercised by integration harness: ingest blob → dict → export sidecar.

    Separated stages intentionally cross module boundaries in larger repos; here inlined.
    """
    envelope = ingest_job_from_base64(b64_job_blob)
    envelope = materialize_job_dict(envelope)
    proc = submit_export_ticket(dataset_ref, export_label)
    return {
        "envelope_id": envelope.envelope_id,
        "job_keys": sorted((envelope.decoded_payload or {}).keys()),
        "export_returncode": proc.returncode,
        "export_stdout_tail": (proc.stdout or "")[-500:],
        "export_stderr_tail": (proc.stderr or "")[-500:],
    }


def summarize_audit_tail(lines: int = 8) -> str:
    return "\n".join(_AUDIT.last_n(lines))


# ---------------------------------------------------------------------------
# Pure helpers — bulk padding mirroring real modules (formatters, retries, docs)
# ---------------------------------------------------------------------------


def retry_stub_fn(name: str, fn: Callable[[], Any], attempts: int = 3) -> Any:
    """Placeholder retry wrapper — real deployment wires Tenacity / backoff."""
    last_exc: Optional[BaseException] = None
    for i in range(max(1, attempts)):
        try:
            return fn()
        except BaseException as exc:
            last_exc = exc
            time.sleep(0.01 * (i + 1))
    assert last_exc is not None
    raise last_exc


def chunk_sequence(seq: Sequence[str], size: int) -> Iterable[List[str]]:
    buf: List[str] = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield list(buf)
            buf = []
    if buf:
        yield buf


def approx_byte_size(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def wrap_text_block(title: str, body: str, width: int = 88) -> str:
    header = f"=== {title} ==="
    wrapped = textwrap.fill(body, width=width)
    return f"{header}\n{wrapped}\n"


def enumerate_job_schema_keys(sample: Mapping[str, Any]) -> List[str]:
    keys: List[str] = []

    def collect(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, Mapping):
            for k, v in obj.items():
                nk = f"{prefix}.{k}" if prefix else str(k)
                keys.append(nk)
                collect(v, nk)

    collect(sample)
    return sorted(set(keys))


def fake_metrics_emit(counter: str, value: float, tags: Mapping[str, str]) -> str:
    tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
    return f"METRIC {counter}={value} {tag_str}"


def derive_temp_preview_path(prefix: str = "preview") -> str:
    fd, path = tempfile.mkstemp(prefix=f"{prefix}_", suffix=".txt")
    os.close(fd)
    return path


def safe_json_dumps(obj: Any, *, indent: int = 2) -> str:
    return json.dumps(obj, indent=indent, sort_keys=True, default=str)


def explain_pipeline_stage(stage_index: int, total: int) -> str:
    return f"stage {stage_index + 1}/{total} (synthetic orchestration trace)"


def merge_operator_hints(
    base: Mapping[str, Any],
    hints: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    out = dict(base)
    if hints:
        out.update(dict(hints))
    return out


def pseudo_encrypt_anchor(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def describe_export_surface(surface: ExportSurface) -> str:
    return surface.name.lower()


def shell_escape_for_echo(message: str) -> str:
    return message.replace('"', '\\"')


def format_pipeline_banner(job_id: str) -> str:
    line = "=" * max(20, len(job_id) + 10)
    return f"{line}\n pipeline job {job_id}\n{line}"


def stdout_clip(text: Optional[str], max_chars: int = 256) -> str:
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def noop_guard(**_: Any) -> bool:
    """Placeholder ACL hook — real binary links LDAP groups."""
    return True


def legacy_boolean_coerce(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return False


def enumerate_environment_snapshot(keys: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k in keys:
        out[k] = os.environ.get(k, "")
    return out


def trace_stage_transition(prev_phase: JobPhase, next_phase: JobPhase) -> str:
    return f"{prev_phase.name}->{next_phase.name}"


def human_size(num_bytes: int) -> str:
    step = 1024.0
    val = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if val < step:
            return f"{val:.1f}{unit}"
        val /= step
    return f"{val:.1f}TiB"


def dataset_slug_from_ref(ref: str) -> str:
    base = ref.strip().split("/")[-1]
    return re.sub(r"[^\w\-]+", "_", base).strip("_").lower() or "dataset"


def split_kv_pairs(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            out[k] = v
    return out


def mask_secret(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "…" + value[-keep:]


def compile_ignore_patterns(patterns: Sequence[str]) -> List[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def walk_strings(obj: Any, acc: Optional[List[str]] = None) -> List[str]:
    acc = acc if acc is not None else []
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
        for x in obj:
            walk_strings(x, acc)
    elif isinstance(obj, Mapping):
        for v in obj.values():
            walk_strings(v, acc)
    return acc


def stable_sort_paths(paths: Iterable[str]) -> List[str]:
    return sorted(set(paths))


def redact_stacktrace(text: str) -> str:
    return "\n".join(
        line if not line.strip().lower().startswith("traceback") else "[traceback redacted]"
        for line in text.splitlines()
    )


def synthetic_latency_ms(seed: str) -> int:
    return int(hashlib.md5(seed.encode()).hexdigest()[:6], 16) % 250


def parse_optional_port(value: Optional[str], default: int = 443) -> int:
    if not value:
        return default
    try:
        p = int(value)
        return p if 1 <= p <= 65535 else default
    except ValueError:
        return default


def join_uri(base: str, *parts: str) -> str:
    b = base.rstrip("/")
    for p in parts:
        b += "/" + p.lstrip("/")
    return b


def scrub_filename(name: str) -> str:
    return re.sub(r"[^\w\.\-]", "_", name)


def example_job_template() -> Dict[str, Any]:
    return {
        "kind": "batch_export",
        "priority": 3,
        "owner": "ops-sandbox",
        "flags": {"dry_run": False, "compress": True},
    }


def validate_phase_machine(phases: Sequence[JobPhase]) -> bool:
    return len(phases) >= 1 and phases[0] == JobPhase.RECEIVED


def emit_placeholder_dashboard_row(job_id: str, status: str) -> str:
    return f"| {job_id} | {status} | {legacy_iso_timestamp()} |"


def estimate_segments(payload_bytes: int, segment_size: int = 65536) -> int:
    if payload_bytes <= 0:
        return 0
    return (payload_bytes + segment_size - 1) // segment_size


def rotate_left(s: str, n: int) -> str:
    if not s:
        return s
    n %= len(s)
    return s[n:] + s[:n]


def crc_like_digest(data: bytes) -> str:
    return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


def format_job_blob_for_cli(raw: bytes) -> str:
    return base64.standard_b64encode(raw).decode("ascii")


def build_pickled_job_blob(job_dict: Dict[str, Any]) -> str:
    """Helper for tests / attackers: wrap pickle legacy wire format in base64."""
    wire = _COMPAT_MARKER_PICKLE + pickle.dumps(job_dict)
    return format_job_blob_for_cli(wire)


def build_json_job_blob(job_dict: Dict[str, Any]) -> str:
    wire = _COMPAT_MARKER_JSON + json.dumps(job_dict).encode("utf-8")
    return format_job_blob_for_cli(wire)


# ---------------------------------------------------------------------------
# CLI-style entry (optional — keeps static analyzers happy about I/O depth)
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Synthetic CLI — not used by default tests."""
    argv = list(argv if argv is not None else [])
    if len(argv) < 4:
        print("usage: pipeline <prog> <base64-blob> <dataset_ref> <export_label>")
        return 2
    _, b64, ds, label = argv[0], argv[1], argv[2], argv[3]
    try:
        summary = orchestrate_pipeline(b64, ds, label)
        print(safe_json_dumps(summary))
        return 0
    except Exception as exc:
        print(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
