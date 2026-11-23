"""Reproducible selective policy; empirical risk control, not a safety guarantee."""

from collections import defaultdict

import numpy as np
from scipy.stats import norm

THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.975, 0.99, 0.995, 0.999, 1.0)


def wilson_upper(errors, total, alpha=0.05):
    if not total:
        return 1.0
    z = norm.ppf(1 - alpha)
    p = errors / total
    return float(
        (p + z * z / (2 * total) + z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)))
        / (1 + z * z / total)
    )


def choose_threshold(probabilities, labels, groups, eligible, max_risk=0.01, min_groups=100):
    """Count any unsafe recommendation in a related-file group as a group failure.

    Use a Bonferroni-adjusted one-sided Wilson upper bound over a fixed grid.
    Wilson is approximate and assumes independent groups; distribution shift can
    invalidate it. Policy data is never reused for fitting or reported as test data.
    """
    selected = None
    diagnostics = []
    for threshold in THRESHOLDS:
        failures = defaultdict(bool)
        accepted = 0
        for prob, label, group, allow in zip(probabilities, labels, groups, eligible):
            if allow and prob >= threshold:
                accepted += 1
                failures[group] |= label != "safe"
        bound = wilson_upper(sum(failures.values()), len(failures), 0.05 / len(THRESHOLDS))
        row = {
            "threshold": threshold,
            "accepted": accepted,
            "groups": len(failures),
            "unsafe_groups": sum(failures.values()),
            "risk_upper_bound": bound,
        }
        diagnostics.append(row)
        if selected is None and len(failures) >= min_groups and bound <= max_risk:
            selected = threshold
    return {
        "threshold": selected,
        "max_risk": max_risk,
        "min_groups": min_groups,
        "method": "one-sided Wilson; Bonferroni fixed grid; approximate independent-group bound",
        "diagnostics": diagnostics,
    }


def metrics(labels, decisions):
    labels, decisions = np.array(labels), np.array(decisions)
    recommended = decisions == "safe"
    important = labels == "important"
    safe_count = int(recommended.sum())
    unsafe = int(((labels != "safe") & recommended).sum())
    return {
        "n": len(labels),
        "recommended": safe_count,
        "safe_precision": float(((labels == "safe") & recommended).sum() / safe_count)
        if safe_count
        else None,
        "false_safe_rate": float((important & recommended).sum() / important.sum())
        if important.any()
        else None,
        "unsafe_recommendations": unsafe,
        "unknown_recommended": int(((labels == "unknown") & recommended).sum()),
        "recommendation_coverage": float(recommended.mean()) if len(labels) else 0.0,
        "abstention_rate": float((decisions == "unknown").mean()) if len(labels) else 0.0,
        "decision_coverage": float((decisions != "unknown").mean()) if len(labels) else 0.0,
    }
