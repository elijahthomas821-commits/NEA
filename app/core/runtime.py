"""Process start-up helpers."""

from __future__ import annotations

import gc


def freeze_startup_objects() -> None:
    """Move everything allocated at start-up (modules, config, the ORM registry) out of the
    garbage collector's view. Full collections then scan only request-time objects, which
    removes the latency spikes seen when an evaluation allocates thousands of comps."""
    gc.collect()
    gc.freeze()
