"""Keep run secrets (the LLM API key) out of everything agentrig writes.

The key must reach the agent -- it is the agent's own credential -- but it must
never land in the report, the SARIF, the markdown, or any captured stream.
The transport is handled by the backend (an inherited pipe fd, never argv or
disk); this module is the other half: a scrubber applied to every captured
stream as it is collected *and*, as a catch-all, to the whole report dict
before it is hash-chained and signed.

It redacts the verbatim value and its common encodings (see
:mod:`agentrig.observe.matching`). A hostile agent that deliberately obfuscates
its own key in a bespoke way cannot be fully prevented from echoing it into
its stdout; the README says so.
"""

from __future__ import annotations

from typing import Any

from agentrig.observe.matching import encoded_forms

REDACTED = "[REDACTED:{name}]"


class Scrubber:
    """Redacts registered secret values from strings and nested structures."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        # name -> list of textual forms (longest first, so a hex form is not
        # half-replaced by a shorter overlapping form)
        self._forms: list[tuple[str, str]] = []
        for name, value in (secrets or {}).items():
            self.add(name, value)

    def add(self, name: str, value: str) -> None:
        if not value:
            return
        for form in encoded_forms(value.encode("utf-8")):
            text = form.decode("utf-8", "replace")
            if text and (text, name) not in self._forms:
                self._forms.append((text, name))
        self._forms.sort(key=lambda f: -len(f[0]))

    def __bool__(self) -> bool:
        return bool(self._forms)

    def text(self, s: str) -> str:
        if not self._forms or not s:
            return s
        for form, name in self._forms:
            if form in s:
                s = s.replace(form, REDACTED.format(name=name))
        return s

    def contains_secret(self, blob: bytes | str) -> bool:
        if not self._forms:
            return False
        s = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        return any(form in s for form, _ in self._forms)

    def deep(self, obj: Any) -> Any:
        """Scrub every string (dict keys included) in a JSON-like structure."""
        if not self._forms:
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.deep(x) for x in obj]
        if isinstance(obj, tuple):
            return [self.deep(x) for x in obj]
        if isinstance(obj, dict):
            return {self.text(k) if isinstance(k, str) else k: self.deep(v)
                    for k, v in obj.items()}
        return obj
