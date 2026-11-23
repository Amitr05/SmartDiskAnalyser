"""Measured local engineering benchmark, not fabricated research results."""

import platform
import statistics
import time

import numpy as np

from .ml.data import load_jsonl
from .query import answer


def distribution(samples):
    return {
        "n": len(samples),
        "median_seconds": statistics.median(samples),
        "p95_seconds": float(np.quantile(samples, 0.95)),
        "samples_seconds": samples,
    }


def benchmark(db, root, cases_path, repeats=3, exclude=()):
    if not 1 <= repeats <= 20:
        raise ValueError("repeats must be 1..20")
    cases = load_jsonl(cases_path)
    valid = {"largest", "summary", "forecast", "safety", "duplicates", "anomalies", "applications", "unknown"}
    if not cases or any(not r.get("question") or r.get("expected_intent") not in valid for r in cases):
        raise ValueError("Need nonempty JSONL with question and valid expected_intent")
    scans = [db.scan(root, exclude) for _ in range(repeats)]
    scan = scans[-1]
    results, timings = [], []
    for case in cases:
        per_case = []
        for _ in range(repeats):
            start = time.perf_counter()
            result = answer(db, scan, case["question"])
            elapsed = time.perf_counter() - start
            timings.append(elapsed)
            per_case.append(elapsed)
        results.append(
            {
                "question": case["question"],
                "expected": case["expected_intent"],
                "actual": result["intent"],
                "correct": result["intent"] == case["expected_intent"],
                "latency": distribution(per_case),
            }
        )
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "scope": str(root),
        "repeats": repeats,
        "scan_latency": distribution([s["elapsed"] for s in scans]),
        "scans": scans,
        "query_latency": distribution(timings),
        "query_cases": results,
        "intent_accuracy": sum(r["correct"] for r in results) / len(results),
        "notes": [
            "Repeated scans are warm/mixed-cache, not controlled cold-cache benchmarks.",
            "Intent accuracy is not free-form chatbot factual accuracy.",
            "Use independent paraphrases and manually check result grounding before reporting.",
        ],
    }
