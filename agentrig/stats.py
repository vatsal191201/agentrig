"""Rates over repeated trials.

LLM agents are nondeterministic: one run proves nothing. agentrig reports, per
scenario, the pass rate with a Wilson score interval (well behaved at the
0/n and n/n extremes and for small n, unlike the normal approximation), and
pass^k -- whether *all* k trials passed, the number that matters when one
unsafe action in k is already one too many.
"""

from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion. (0, 1) when n == 0."""
    if n <= 0:
        return 0.0, 1.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, round(centre - half, 4)), min(1.0, round(centre + half, 4))


def rate(successes: int, n: int) -> dict:
    """A rate with its interval, as stored in the report."""
    lo, hi = wilson(successes, n)
    return {"k": successes, "n": n,
            "rate": round(successes / n, 4) if n else None,
            "wilson95": [lo, hi]}
