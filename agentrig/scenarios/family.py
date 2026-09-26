"""Scenario families: one JSON template, many variants.

A family file carries ``variants`` and an ``expectation`` split into
``perturbed`` and ``control``. Each variant becomes an ordinary scenario with
id ``<family>.<variant>``: its ``vars`` fill ``{{VAR_<NAME>}}`` placeholders
in the template (non-string values are JSON-encoded), and it takes the
perturbed or control expectation. The report then aggregates the family:
catch rate (perturbed variants the agent aborted) and false-stop rate
(control variants it aborted), using the template's ``abort_signal``.
"""

from __future__ import annotations

import copy
import json

from agentrig.errors import ScenarioError
from agentrig.util import substitute_deep


def expand_family(raw: dict) -> list[dict]:
    fid = raw.get("id", "?")
    variants = raw.get("variants")
    exp = raw.get("expectation") or {}
    if not isinstance(variants, list) or not variants:
        raise ScenarioError(f"family {fid!r}: 'variants' must be a non-empty list")
    if not isinstance(exp.get("perturbed"), dict) or not isinstance(exp.get("control"), dict):
        raise ScenarioError(f"family {fid!r}: expectation needs 'perturbed' and 'control'")
    if not raw.get("abort_signal"):
        raise ScenarioError(f"family {fid!r}: needs an 'abort_signal'")
    base = {k: v for k, v in raw.items() if k not in ("variants", "expectation")}
    out: list[dict] = []
    seen: set[str] = set()
    for i, var in enumerate(variants):
        vid = var.get("id") if isinstance(var, dict) else None
        if not vid or vid in seen or not isinstance(var.get("perturbed"), bool):
            raise ScenarioError(f"family {fid!r}: variant #{i} needs a unique 'id' "
                                "and a boolean 'perturbed'")
        seen.add(vid)
        mapping = {"{{VAR_%s}}" % k.upper(): v if isinstance(v, str) else json.dumps(v)
                   for k, v in (var.get("vars") or {}).items()}
        d = substitute_deep(copy.deepcopy(base), mapping)
        d.update(id=f"{fid}.{vid}", title=f"{raw.get('title', fid)} [{vid}]",
                 family=fid, variant=vid, perturbed=var["perturbed"],
                 description=(raw.get("description", "") + " Variant: "
                              + var.get("description", vid)).strip(),
                 expectation=copy.deepcopy(exp["perturbed" if var["perturbed"]
                                               else "control"]))
        out.append(d)
    return out
