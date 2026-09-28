"""Enforce per-package coverage floors on top of the global ``--cov-fail-under``.

Money-critical packages (profit, market pricing, deal rules) must stay above 90% line
coverage. Usage: ``python scripts/check_coverage.py coverage.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FLOORS = {
    "app/analysis/profit/": 90.0,
    "app/analysis/market/": 90.0,
    "app/analysis/deals/": 90.0,
}


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    files = data["files"]
    failed = False
    for prefix, floor in FLOORS.items():
        covered = total = 0
        for name, info in files.items():
            if name.replace("\\", "/").startswith(prefix):
                summary = info["summary"]
                covered += summary["covered_lines"]
                total += summary["num_statements"]
        if total == 0:
            print(f"{prefix:<28} not present yet (skipped)")
            continue
        pct = 100.0 * covered / total
        status = "ok" if pct >= floor else "FAIL"
        print(f"{prefix:<28} {pct:6.2f}% (floor {floor:.0f}%) {status}")
        failed |= pct < floor
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
