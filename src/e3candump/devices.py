"""Load device configuration from a devices.json file (open3e format)."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_devices(path: str) -> dict[tuple[int, int], str]:
    """Read devices.json and return {(req_id, rsp_id): device_name}.

    Returns an empty dict if the file does not exist.
    S77 channel pair: req = tx + 0x02, rsp = tx + 0x12.
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with p.open() as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"e3candump: warning: cannot read {path}: {exc}", file=sys.stderr)
        return {}

    pairs: dict[tuple[int, int], str] = {}
    for entry in data.values():
        try:
            tx = int(entry["tx"], 16)
        except (KeyError, ValueError):
            continue
        name = entry.get("prop") or hex(tx)
        pairs[(tx + 0x02, tx + 0x12)] = name
    return pairs
