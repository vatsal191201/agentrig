"""Optional ed25519 signing that degrades to an unsigned hash chain.

If the ``cryptography`` extra is installed we sign the report's chain head with
an ed25519 key persisted (0600) under the user state dir -- outside the repo,
never committed. If it is not installed we say so plainly and rely on the hash
chain alone for tamper-evidence.

Honesty note: a report embeds its own public key, so a valid signature proves
the report was not altered *after signing by whoever holds that private key*.
To attribute it to a specific signer, pin the public key out of band (its
fingerprint is printed by ``agentrig doctor``). The hash chain stands on its
own regardless.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:  # optional dependency
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - exercised only when extra is absent
    _HAVE_CRYPTO = False


def crypto_available() -> bool:
    return _HAVE_CRYPTO


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    d = Path(base) / "agentrig"
    d.mkdir(parents=True, exist_ok=True)
    return d


class Signer:
    """Loads or creates a persistent ed25519 identity for this host/user."""

    def __init__(self, key_path: Optional[Path] = None) -> None:
        self._key_path = key_path or (_state_dir() / "ed25519.key")
        self._priv = None
        if _HAVE_CRYPTO:
            self._priv = self._load_or_create()

    @property
    def available(self) -> bool:
        return self._priv is not None

    def _load_or_create(self):
        if self._key_path.exists():
            raw = bytes.fromhex(self._key_path.read_text().strip())
            return Ed25519PrivateKey.from_private_bytes(raw)
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        # Write 0600 before anything sensitive lands in it.
        fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(raw.hex())
        return priv

    def public_key_hex(self) -> Optional[str]:
        if not self.available:
            return None
        pub = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pub.hex()

    def fingerprint(self) -> Optional[str]:
        """A short human-comparable id for the public key."""
        pk = self.public_key_hex()
        if pk is None:
            return None
        import hashlib
        return hashlib.sha256(bytes.fromhex(pk)).hexdigest()[:16]

    def sign_hex(self, data: bytes) -> Optional[str]:
        if not self.available:
            return None
        return self._priv.sign(data).hex()


def verify_signature(public_key_hex: str, data: bytes, signature_hex: str) -> bool:
    """Verify an ed25519 signature. Raises RuntimeError if crypto is absent."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed; cannot verify signature")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False
