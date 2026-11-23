"""Storage aggregation, learned anomalies, application hints and temporal regression."""

import json
import math
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error


def largest(db, scan_id, limit=20):
    return [
        json.loads(r[0])
        for r in db.conn.execute(
            """SELECT metadata FROM files
        WHERE scan_id=? AND is_directory=0 ORDER BY size DESC,path LIMIT ?""",
            (scan_id, limit),
        )
    ]


def directories(db, scan):
    """Aggregate direct-parent sizes, then propagate: no repeated subtree scanning."""
    root = Path(scan["root"])
    totals = defaultdict(lambda: {"bytes": 0, "files": 0, "max_file": 0})
    for row in db.conn.execute(
        """SELECT parent,SUM(size),COUNT(*),MAX(size) FROM files
                                 WHERE scan_id=? AND is_directory=0 GROUP BY parent""",
        (scan["id"],),
    ):
        path = Path(row[0])
        while path == root or root in path.parents:
            value = totals[str(path)]
            value["bytes"] += row[1]
            value["files"] += row[2]
            value["max_file"] = max(value["max_file"], row[3])
            if path == root:
                break
            path = path.parent
    return [{"path": key, **value} for key, value in totals.items()]


def summary(db, scan):
    breakdown = [
        dict(r)
        for r in db.conn.execute(
            """SELECT extension,COUNT(*) AS files,SUM(size) AS bytes
                 FROM files WHERE scan_id=? AND is_directory=0 GROUP BY extension ORDER BY bytes DESC""",
            (scan["id"],),
        )
    ]
    errors = [
        dict(r)
        for r in db.conn.execute("SELECT path,error FROM scan_errors WHERE scan_id=? LIMIT 50", (scan["id"],))
    ]
    return {
        "scan": scan,
        "largest_files": largest(db, scan["id"]),
        "largest_directories": sorted(directories(db, scan), key=lambda r: -r["bytes"])[:20],
        "extension_breakdown": breakdown,
        "errors_first_50": errors,
        "caveat": "Directory/path totals are logical and overlapping. Unique inode bytes and allocated "
        "bytes are reported separately. Scan may be partial; check status.",
    }


def anomalies(db, scan):
    rows = [r for r in directories(db, scan) if r["path"] != scan["root"]]
    if len(rows) < 16:
        return {
            "status": "insufficient_data",
            "reason": "At least 16 non-root directory observations required.",
        }
    x = [
        [
            math.log1p(r["bytes"]),
            math.log1p(r["files"]),
            math.log1p(r["max_file"]),
            math.log1p(r["bytes"] / r["files"]),
            len(Path(r["path"]).parts),
        ]
        for r in rows
    ]
    model = IsolationForest(n_estimators=120, contamination="auto", random_state=42).fit(x)
    scores = -model.score_samples(x)
    predictions = model.predict(x)
    flagged = sorted(
        [
            {**row, "anomaly_score": float(score)}
            for row, score, pred in zip(rows, scores, predictions)
            if pred == -1
        ],
        key=lambda r: -r["anomaly_score"],
    )[:20]
    return {
        "status": "ok",
        "method": "IsolationForest fitted to this scan, relative structural outliers only",
        "directories_observed": len(rows),
        "results": flagged,
        "warning": "Nested directories are dependent. Anomaly is not evidence of dispensability or malware.",
    }


APP_HINTS = {
    "docker": ("docker",),
    "Android SDK / Studio": ("android", "android studio", "sdk"),
    "Chrome": ("chrome",),
    "Edge": ("edge",),
    "Steam": ("steam", "steamapps"),
    "VS Code": ("code", ".vscode"),
    "Python environment": (".venv", "venv", "python"),
    "Node dependencies / npm": ("node_modules", "npm", "_cacache"),
    "Gradle": (".gradle",),
    "Maven": (".m2",),
    "pip": ("pip",),
    "Java": ("jdk", "java"),
}


def applications(db, scan):
    from .knowledge import location, parts

    result = defaultdict(lambda: defaultdict(int))
    for rec in db.records(scan["id"]):
        p = set(parts(rec["path"]))
        for name, tokens in APP_HINTS.items():
            if p.intersection(tokens):
                result[name][location(rec["path"])] += rec["size"]
                break
    return {
        "source": "path hints, not a verified installed-application inventory",
        "applications": [
            {"name": k, "logical_bytes": sum(v.values()), "contexts": dict(v)}
            for k, v in sorted(result.items(), key=lambda pair: -sum(pair[1].values()))
        ],
        "warning": "No Docker commands executed. Volumes may contain persistent databases/user data.",
    }


def forecast(db, root, capacity=None, exclusions="[]"):
    observations = db.conn.execute(
        """SELECT h.timestamp,h.bytes FROM storage_history h LEFT JOIN scans s ON h.scan_id=s.id
            WHERE h.root=? AND COALESCE(s.exclusions,'[]')=? ORDER BY h.timestamp""",
        (root, exclusions),
    ).fetchall()
    # Multiple scans on the same UTC date are not independent daily history.
    days = {}
    for t, size in observations:
        day = datetime.fromtimestamp(t, UTC).date().isoformat()
        days[day] = (t, size)
    history = list(days.values())
    if len(history) < 5 or history[-1][0] - history[0][0] < 7 * 86400:
        return {
            "status": "insufficient_history",
            "observed_days": len(history),
            "reason": "Need at least 5 distinct dates spanning 7 days of complete scans of the same root.",
        }
    start = history[0][0]
    x = np.array([[(t - start) / 86400] for t, _ in history])
    y = np.array([s for _, s in history], dtype=float)
    # Expanding-window temporal holdout errors, not training residuals.
    errors, actuals, predictions = [], [], []
    for i in range(3, len(history)):
        trial = LinearRegression().fit(x[:i], y[:i])
        pred = float(trial.predict(x[i : i + 1])[0])
        errors.append(abs(pred - y[i]))
        actuals.append(y[i])
        predictions.append(pred)
    model = LinearRegression().fit(x, y)
    width = float(np.quantile(errors, 0.95))
    future = []
    for horizon in (7, 30, 60):
        pred = max(0.0, float(model.predict([[x[-1, 0] + horizon]])[0]))
        future.append(
            {
                "days": horizon,
                "predicted_bytes": round(pred),
                "empirical_error_band": [round(max(0, pred - width)), round(pred + width)],
            }
        )
    slope = float(model.coef_[0])
    exhaustion = None
    if capacity is not None and slope > 0:
        exhaustion = max(0.0, (capacity - float(y[-1])) / slope)
    return {
        "status": "ok",
        "scope": root,
        "method": "LinearRegression on daily complete-scan unique bytes",
        "observed_days": len(history),
        "daily_growth_bytes": slope,
        "forecast": future,
        "temporal_mae_bytes": float(mean_absolute_error(actuals, predictions)),
        "temporal_rmse_bytes": float(np.sqrt(mean_squared_error(actuals, predictions))),
        "estimated_days_to_scope_capacity": exhaustion,
        "warning": "Error bands are descriptive backtest errors, not calibrated prediction intervals. "
        "A directory scan is not total drive usage. Capacity must refer to this scope.",
    }


def compare(db, first, second):
    a, b = db.latest(first), db.latest(second)
    if a["root"] != b["root"] or a.get("exclusions") != b.get("exclusions"):
        raise ValueError("Comparison requires the same scan root and exclusions")
    rows = db.conn.execute(
        """SELECT b.path,b.size-a.size AS delta_bytes FROM files a JOIN files b
        ON a.path=b.path WHERE a.scan_id=? AND b.scan_id=? AND a.is_directory=0 AND b.is_directory=0
        AND a.size != b.size ORDER BY delta_bytes DESC LIMIT 50""",
        (a["id"], b["id"]),
    )
    counts = {}
    for name, left, right in [("added", b, a), ("removed", a, b)]:
        counts[name] = db.conn.execute(
            """SELECT COUNT(*) FROM files l WHERE l.scan_id=?
            AND l.is_directory=0 AND NOT EXISTS (SELECT 1 FROM files r WHERE r.scan_id=? AND r.path=l.path)""",
            (left["id"], right["id"]),
        ).fetchone()[0]
    return {
        "first": a,
        "second": b,
        "unique_bytes_delta": b["unique_bytes"] - a["unique_bytes"],
        "changed_first_50": [dict(r) for r in rows],
        **counts,
        "warning": "Partial scans, renames and hard links can affect comparisons.",
    }
