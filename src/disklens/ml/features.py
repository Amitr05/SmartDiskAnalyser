"""Fixed, auditable feature extraction; never use labels, raw paths, or device IDs."""

import math
import time

from ..knowledge import location

NUMERIC = ["log_size", "modified_days", "depth", "hidden", "system", "readonly", "linked"]


def features(record, now=None):
    now = time.time() if now is None else now
    modified = record.get("modified_days")
    if modified is None:
        modified = max(0, (now - float(record["mtime_ns"]) / 1e9) / 86400)
    return {
        "extension": str(record.get("extension", "")).lower() or "<none>",
        "location": record.get("location") or location(record["path"]),
        "log_size": math.log1p(max(0, int(record["size"]))),
        "modified_days": min(36500.0, max(0.0, float(modified))),
        "depth": float(record.get("depth", 0)),
        "hidden": float(record.get("is_hidden", False)),
        "system": float(record.get("is_system", False)),
        "readonly": float(record.get("is_readonly", False)),
        "linked": float(record.get("is_link", False) or int(record.get("nlink", 1)) > 1),
    }
