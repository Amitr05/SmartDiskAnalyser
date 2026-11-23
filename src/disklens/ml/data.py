"""Dataset validation, independent annotations and strict cross-device splits."""

import hashlib
import json
import math
import random
from pathlib import Path

from sklearn.metrics import cohen_kappa_score

LABELS = {"safe", "important", "unknown"}
SPLITS = {"train", "calibration", "policy", "test"}


def load_jsonl(path):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate(rows):
    if not rows:
        raise ValueError("Empty dataset")
    owners, seen_ids = {}, set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each dataset row must be a JSON object")  # noqa: TRY004 -- dataset schema error
        required = (
            "record_id",
            "device_id",
            "user_id",
            "split",
            "sha256",
            "related_group",
            "label",
            "category",
            "priority",
            "evidence",
            "path",
            "extension",
            "size",
            "modified_days",
        )
        if any(k not in row for k in required):
            raise ValueError(f"Dataset requires fields: {required}")
        for field in (
            "record_id",
            "device_id",
            "user_id",
            "split",
            "related_group",
            "label",
            "category",
            "priority",
        ):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"{field} must be a nonempty string")
        if row.get("is_directory"):
            raise ValueError("This supervised pipeline is file-only; use directory aggregates separately")
        if row["record_id"] in seen_ids:
            raise ValueError("Duplicate record_id")
        seen_ids.add(row["record_id"])
        if row["split"] not in SPLITS or row["label"] not in LABELS:
            raise ValueError("Invalid split or label")
        if (
            not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in row["sha256"])
        ):
            raise ValueError("sha256 must be a full lower-case SHA-256 content hash")
        if not row["evidence"] or not str(row["related_group"]).strip():
            raise ValueError("Evidence and related_group must be nonempty")
        if (
            not isinstance(row["path"], str)
            or not row["path"].strip()
            or not isinstance(row["category"], str)
            or not row["category"].strip()
            or not isinstance(row["extension"], str)
        ):
            raise ValueError("Path, extension and category must be valid strings")
        for field in ("size", "modified_days", "depth"):
            value = row.get(field, 0)
            if not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{field} must be finite and nonnegative")
        for field in ("is_hidden", "is_system", "is_readonly", "is_link"):
            if field in row and not isinstance(row[field], bool):
                raise ValueError(f"{field} must be a boolean")
        if row["priority"] not in {"high", "medium", "low", "retain", "unknown"}:
            raise ValueError("Invalid cleanup priority")
        for kind in ("device_id", "user_id", "sha256", "related_group"):
            key = kind, str(row[kind])
            if not key[1].strip():
                raise ValueError(f"Empty {kind}")
            if key in owners and owners[key] != row["split"]:
                raise ValueError(f"Leakage: {kind} crosses {owners[key]} and {row['split']}")
            owners[key] = row["split"]
    parts = {name: [r for r in rows if r["split"] == name] for name in SPLITS}
    if any(not subset for subset in parts.values()):
        raise ValueError("Require independent train/calibration/policy/test partitions")
    for name in ("train", "calibration"):
        if {r["label"] for r in parts[name]} != LABELS:
            raise ValueError(f"{name} must include safe, important and unknown")
    return parts


def reconcile(first, second, adjudications=()):
    """Annotators cannot silently drop records; unresolved disagreements are unknown."""
    a, b = {}, {}
    for source, dest in ((first, a), (second, b)):
        for row in source:
            if row["record_id"] in dest or row["label"] not in LABELS or not row.get("evidence"):
                raise ValueError("Invalid or duplicate annotation; evidence is required")
            if not row.get("annotator_id"):
                raise ValueError("annotator_id is required")
            dest[row["record_id"]] = row
    if set(a) != set(b) or not a:
        raise ValueError("Both annotators must label the same nonempty set independently")
    judges = {r["record_id"]: r for r in adjudications}
    resolved, disagreements = [], 0
    for key in sorted(a):
        if a[key]["annotator_id"] == b[key]["annotator_id"]:
            raise ValueError("Annotators must be independent people")
        same = a[key]["label"] == b[key]["label"]
        disagreements += not same
        final, source = (a[key]["label"], "agreement") if same else ("unknown", "unresolved disagreement")
        if not same and key in judges:
            judge = judges[key]
            if (
                judge.get("label") not in LABELS
                or not judge.get("evidence")
                or judge.get("annotator_id") in {None, a[key]["annotator_id"], b[key]["annotator_id"]}
            ):
                raise ValueError("Adjudicator must be independent, with a valid label and evidence")
            final, source = judge["label"], "independent adjudication"
        resolved.append(
            {
                "record_id": key,
                "label": final,
                "resolution": source,
                "annotations": [a[key], b[key]],
                "adjudication": judges.get(key),
            }
        )
    la, lb = [a[k]["label"] for k in sorted(a)], [b[k]["label"] for k in sorted(a)]
    kappa = None if len(set(la + lb)) == 1 else float(cohen_kappa_score(la, lb))
    return {
        "n": len(a),
        "agreement": 1 - disagreements / len(a),
        "cohen_kappa": kappa,
        "disagreements": disagreements,
        "resolved": resolved,
    }


def demo_dataset(count=180, seed=42):
    """Synthetic plumbing ONLY. No measured claim about real Windows files."""
    rng, rows = random.Random(seed), []
    for device, split in enumerate(("train", "calibration", "policy", "test")):
        for i in range(count):
            label = ("safe", "important", "unknown")[i % 3]
            loc = {"safe": "Temp", "important": "Documents", "unknown": "Mystery"}[label]
            ext = rng.choice(
                {
                    "safe": [".tmp", ".cache", ".log"],
                    "important": [".docx", ".pdf", ".db"],
                    "unknown": [".bin", ".dat", ".x"],
                }[label]
            )
            key = f"synthetic-{device}-{i}"
            # Controlled label noise makes this a demo, not a trivial proof of safety.
            noisy_label = rng.choice(sorted(LABELS)) if rng.random() < 0.08 else label
            rows.append(
                {
                    "record_id": key,
                    "device_id": f"demo-device-{device}",
                    "user_id": f"demo-user-{device}",
                    "split": split,
                    "sha256": hashlib.sha256(key.encode()).hexdigest(),
                    "related_group": key,
                    "label": noisy_label,
                    "category": {"safe": "temporary", "important": "document", "unknown": "unknown"}[label],
                    "priority": {"safe": "high", "important": "retain", "unknown": "unknown"}[label],
                    "path": f"C:/Users/Demo/{loc}/file{i}{ext}",
                    "extension": ext,
                    "size": rng.randint(100, 10**8),
                    "modified_days": rng.randint(1, 700),
                    "depth": 5,
                    "evidence": "SYNTHETIC: generated label, not owner-verified",
                    "synthetic": True,
                }
            )
    return rows
