"""Content matching shared by canary detection, secret scrubbing and receipts.

One question, asked three ways: *does this blob reveal that value?* An agent
that exfiltrates a decoy secret -- or a report that would leak the real API
key -- rarely does it verbatim only. We therefore look for the value itself and
for the cheap, common encodings an agent (or an HTTP library) applies:

    verbatim, URL-quoted, hex (lower/upper), base64 and urlsafe-base64

Base64 is alignment-dependent: a value embedded inside a larger base64 stream
encodes differently depending on its offset mod 3. For each of the three
alignments we keep only the "core" characters determined by the value alone,
so a secret buried in a base64-encoded upload is still found.

Limits (stated, not hidden): paraphrase, partial copies, compression,
encryption, or bespoke encodings are not detected. Matching proves presence;
absence of a match is not proof of absence.
"""

from __future__ import annotations

import base64
import urllib.parse

# Cores shorter than this are too likely to collide with unrelated text.
_MIN_CORE = 8


def _b64_cores(value: bytes, encoder) -> list[bytes]:
    cores = []
    for align in range(3):
        enc = encoder(b"\0" * align + value)
        first = 1 if align else 0  # first block mixes in the dummy prefix
        last = (align + len(value)) // 3  # blocks after this touch unknown suffix
        core = enc[4 * first: 4 * last]
        if len(core) >= _MIN_CORE:
            cores.append(core)
    return cores


def encoded_forms(value: bytes, *, full: bool = True) -> list[bytes]:
    """Byte strings whose presence in a blob reveals ``value``.

    ``full`` adds URL-quoting and hex, which only make sense for short values
    (secrets, canaries); for large files we keep verbatim + base64 cores.
    """
    if not value:
        return []
    forms: list[bytes] = [value]
    forms += _b64_cores(value, base64.b64encode)
    forms += _b64_cores(value, base64.urlsafe_b64encode)
    if full:
        forms.append(urllib.parse.quote(value, safe="").encode("ascii"))
        forms.append(urllib.parse.quote_plus(value).encode("ascii"))
        forms.append(value.hex().encode("ascii"))
        forms.append(value.hex().upper().encode("ascii"))
    out: list[bytes] = []
    for f in forms:
        if f and f not in out:
            out.append(f)
    return out


def reveals(blob: bytes, value: bytes, *, full: bool = True) -> bool:
    """True if ``blob`` contains ``value`` verbatim or in a common encoding."""
    if not value or not blob:
        return False
    return any(f in blob for f in encoded_forms(value, full=full))


def as_bytes(x) -> bytes:
    if isinstance(x, bytes):
        return x
    return str(x).encode("utf-8", "surrogateescape")
