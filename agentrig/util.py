"""Small stdlib-only helpers: hashing, canonical JSON, ids, timestamps.

Kept dependency-free on purpose -- this module underpins the tamper-evident
hash chain, so it must never pull in anything optional.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return the hex SHA-256 of ``text`` encoded as UTF-8."""
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: str | os.PathLike[str], *, chunk: int = 1 << 20) -> str:
    """Return the hex SHA-256 of a file's contents, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Canonical JSON -- deterministic serialization for hashing and signing
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical (deterministic) JSON bytes.

    Sorted keys, compact separators, ``ensure_ascii=True`` so the byte stream
    is stable across platforms. This is the exact representation fed into the
    hash chain and the signature, so both signer and verifier agree.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def canonical_sha256(obj: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``obj``."""
    return sha256_bytes(canonical_json(obj))


# ---------------------------------------------------------------------------
# Identifiers and timestamps
# ---------------------------------------------------------------------------


def new_run_id() -> str:
    """A sortable, collision-resistant run id: ``run-<epoch>-<rand>``."""
    return f"run-{int(time.time())}-{secrets.token_hex(4)}"


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def substitute_deep(obj: Any, mapping: dict[str, str]) -> Any:
    """Recursively replace ``{{KEY}}`` placeholders in strings within ``obj``.

    Walks strings, lists, and dict values (dict keys are left untouched). Used to
    resolve runtime values -- fake-service URLs, canary values, the workdir --
    into scenario files, prompts, service bodies, and check parameters.
    """
    if isinstance(obj, str):
        for key, value in mapping.items():
            if key in obj:
                obj = obj.replace(key, value)
        return obj
    if isinstance(obj, list):
        return [substitute_deep(x, mapping) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute_deep(v, mapping) for k, v in obj.items()}
    return obj


def truncate(text: str, limit: int = 2000) -> str:
    """Truncate ``text`` for evidence capture, marking that it was cut."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def truncate_middle(text: str, limit: int = 4000) -> str:
    """Keep the head *and* the tail (an agent's final answer and last lines are
    the most telling evidence), cutting the middle."""
    if len(text) <= limit:
        return text
    head, tail = limit * 3 // 5, limit * 2 // 5
    return (text[:head] + f"\n...[{len(text) - head - tail} chars truncated]...\n"
            + text[-tail:])
