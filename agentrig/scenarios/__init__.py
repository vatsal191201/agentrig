"""Scenario discovery and loading.

Scenarios ship as JSON under ``scenarios/data/``. They are loaded and validated
into :class:`~agentrig.scenarios.schema.Scenario` objects. Loading uses only the
stdlib ``json`` module; authoring in YAML is possible via the optional ``yaml``
extra but the shipped pack is JSON to keep the core dependency-free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentrig.errors import ScenarioError
from agentrig.scenarios.schema import (
    CHECKS_NEEDING_TRACE,
    KNOWN_CHECK_TYPES,
    Scenario,
    ServiceDef,
    parse_scenario,
)

_DATA_DIR = Path(__file__).parent / "data"

__all__ = [
    "Scenario", "ServiceDef", "parse_scenario", "load_all", "load_one",
    "list_ids", "KNOWN_CHECK_TYPES", "CHECKS_NEEDING_TRACE",
]


def _load_dir(directory: Path) -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    if not directory.is_dir():
        return scenarios
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScenarioError(f"cannot read scenario {path.name}: {exc}") from exc
        scenario = parse_scenario(raw)
        if scenario.id in scenarios:
            raise ScenarioError(f"duplicate scenario id {scenario.id!r} in {path}")
        scenarios[scenario.id] = scenario
    return scenarios


def load_all(extra_dir: str | os.PathLike[str] | None = None) -> dict[str, Scenario]:
    """Load the built-in pack, plus an optional user directory of JSON files."""
    scenarios = _load_dir(_DATA_DIR)
    if extra_dir is not None:
        for sid, scn in _load_dir(Path(extra_dir)).items():
            scenarios[sid] = scn  # user scenarios override built-ins by id
    return scenarios


def load_one(scenario_id: str, extra_dir: str | os.PathLike[str] | None = None) -> Scenario:
    scenarios = load_all(extra_dir)
    try:
        return scenarios[scenario_id]
    except KeyError:
        raise ScenarioError(
            f"unknown scenario {scenario_id!r}; available: "
            f"{', '.join(sorted(scenarios))}") from None


def list_ids(extra_dir: str | os.PathLike[str] | None = None) -> list[str]:
    return sorted(load_all(extra_dir))
