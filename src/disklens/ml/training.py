"""Fit once; calibrate, select policy and test on distinct users/devices."""

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import brier_score_loss, classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.tree import DecisionTreeClassifier

from ..safety import assess
from .data import validate
from .features import features
from .policy import choose_threshold, metrics


def classifier(seed=42, tree=False):
    model = (
        DecisionTreeClassifier(max_depth=8, min_samples_leaf=3, random_state=seed)
        if tree
        else RandomForestClassifier(
            n_estimators=120,
            max_depth=14,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
    )
    return make_pipeline(DictVectorizer(sparse=False), model)


def supported(row, bundle):
    feat = features(row)
    return (
        feat["extension"] in bundle["extensions"]
        and feat["location"] in bundle["locations"]
        and feat["log_size"] <= bundle["max_log_size"] + np.log(10)
    )


def safe_prob(model, x):
    return model.predict_proba(x)[:, list(model.classes_).index("safe")]


def decisions(bundle, rows, veto=True, abstain=True, calibrated=True):
    x = [features(r) for r in rows]
    model = bundle["safety"] if calibrated else bundle["raw_safety"]
    probabilities = safe_prob(model, x)
    predictions = model.predict(x)
    result = []
    threshold = bundle["policy"]["threshold"]
    for row, prob, pred in zip(rows, probabilities, predictions):
        allowed = not veto or assess(row).review_eligible
        if not abstain:
            result.append(
                "safe" if pred == "safe" and allowed else ("important" if pred == "important" else "unknown")
            )
        elif allowed and supported(row, bundle) and threshold is not None and prob >= threshold:
            result.append("safe")
        else:
            result.append("important" if pred == "important" else "unknown")
    return result


def train(rows, output: Path, max_risk=0.01, min_groups=100):
    if not 0 < max_risk < 1 or min_groups < 1:
        raise ValueError("max_risk must be in (0,1), min_groups must be positive")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Use a fresh, empty artifact directory")
    partitions = validate(rows)
    train_rows, cal, policy, test = [partitions[k] for k in ("train", "calibration", "policy", "test")]
    x_train, x_cal, x_policy, x_test = [
        [features(r) for r in part] for part in (train_rows, cal, policy, test)
    ]
    labels = lambda part, key="label": [r[key] for r in part]
    raw = classifier().fit(x_train, labels(train_rows))
    calibrated = CalibratedClassifierCV(FrozenEstimator(raw), method="sigmoid").fit(x_cal, labels(cal))
    category = classifier().fit(x_train, labels(train_rows, "category"))
    priority = classifier().fit(x_train, labels(train_rows, "priority"))
    bundle = {
        "version": 1,
        "created": time.time(),
        "sklearn": sklearn.__version__,
        "synthetic": any(r.get("synthetic", False) for r in rows),
        "safety": calibrated,
        "raw_safety": raw,
        "category": category,
        "priority": priority,
        "extensions": sorted({f["extension"] for f in x_train}),
        "locations": sorted({f["location"] for f in x_train}),
        "max_log_size": max(f["log_size"] for f in x_train),
    }
    bundle["policy"] = choose_threshold(
        safe_prob(calibrated, x_policy),
        labels(policy),
        labels(policy, "related_group"),
        [assess(r).review_eligible and supported(r, bundle) for r in policy],
        max_risk,
        min_groups,
    )
    test_labels = labels(test)
    experiments = {}
    variants = {
        "risk_aware": {},
        "no_veto": {"veto": False},
        "no_abstention": {"abstain": False},
        "no_calibration_fixed_policy": {"calibrated": False},
        "no_controls": {"veto": False, "abstain": False, "calibrated": False},
    }
    for name, kwargs in variants.items():
        experiments[name] = metrics(test_labels, decisions(bundle, test, **kwargs))
    experiments["fixed_rules"] = metrics(
        test_labels,
        [
            "safe"
            if assess(r).review_eligible
            and r["extension"] in {".tmp", ".cache"}
            and features(r)["modified_days"] >= 30
            else "unknown"
            for r in test
        ],
    )
    tree = classifier(tree=True).fit(x_train, labels(train_rows))
    for name, model in [("decision_tree", tree), ("random_forest", raw)]:
        experiments[name] = metrics(test_labels, model.predict(x_test))
    pred = category.predict(x_test)
    safe_y = np.array(test_labels) == "safe"
    prob = safe_prob(calibrated, x_test)
    start = time.perf_counter()
    decisions(bundle, test)
    inference_seconds = time.perf_counter() - start
    vec, forest = category.steps[0][1], category.steps[1][1]
    importance = sorted(
        zip(vec.get_feature_names_out(), forest.feature_importances_), key=lambda pair: pair[1], reverse=True
    )[:12]
    bundle["global_category_importances"] = [(str(name), float(value)) for name, value in importance]
    dataset_digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    source_files = sorted(Path(__file__).parent.glob("*.py")) + [
        Path(__file__).parent.parent / "safety.py",
        Path(__file__).parent.parent / "knowledge.py",
    ]
    source_digest = hashlib.sha256(b"".join(p.read_bytes() for p in source_files)).hexdigest()
    identity_material = f"{dataset_digest}:{source_digest}:{sklearn.__version__}:{max_risk}:{min_groups}"
    bundle["id"] = hashlib.sha256(identity_material.encode()).hexdigest()[:16]
    bundle["source_sha256"] = source_digest
    frame = pd.DataFrame(x_train)
    profile = {
        "numeric_summary": frame.select_dtypes(include="number").describe().to_dict(),
        "location_counts": frame["location"].value_counts().to_dict(),
        "extension_counts_top_20": frame["extension"].value_counts().head(20).to_dict(),
        "safety_label_counts": pd.Series(labels(train_rows)).value_counts().to_dict(),
    }
    report = {
        "model_id": bundle["id"],
        "source_sha256": source_digest,
        "training_profile": profile,
        "safety_classifier_report": classification_report(
            test_labels, calibrated.predict(x_test), output_dict=True, zero_division=0
        ),
        "dataset_sha256": dataset_digest,
        "synthetic_demo_only": bundle["synthetic"],
        "split_counts": {k: len(v) for k, v in partitions.items()},
        "devices": {k: sorted({r["device_id"] for r in v}) for k, v in partitions.items()},
        "policy": bundle["policy"],
        "experiments": experiments,
        "category_report": classification_report(
            labels(test, "category"), pred, output_dict=True, zero_division=0
        ),
        "safety_confusion_labels": ["important", "safe", "unknown"],
        "safety_confusion_matrix": confusion_matrix(
            test_labels, calibrated.predict(x_test), labels=["important", "safe", "unknown"]
        ).tolist(),
        "safe_roc_auc": float(roc_auc_score(safe_y, prob)) if len(set(safe_y)) == 2 else None,
        "safe_brier_score": float(brier_score_loss(safe_y, prob)),
        "priority_report": classification_report(
            labels(test, "priority"), priority.predict(x_test), output_dict=True, zero_division=0
        ),
        "inference_seconds": inference_seconds,
        "seconds_per_file": inference_seconds / len(test),
        "global_category_importances": bundle["global_category_importances"],
        "limitations": [
            "No deletion safety guarantees; labels require owner/context evidence.",
            "Wilson group bound is approximate; distribution shift can invalidate it.",
            "Ablations are offline only. No-calibration ablation holds policy threshold fixed.",
            "Anomaly/forecast/query evaluations require separate histories and review sets.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output / "model.joblib")
    (output / "evaluation.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "model_id": bundle["id"],
                "created": bundle["created"],
                "sklearn": sklearn.__version__,
                "dataset_sha256": dataset_digest,
                "synthetic_demo_only": bundle["synthetic"],
                "split_record_ids": {k: [r["record_id"] for r in v] for k, v in partitions.items()},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return report


def load_model(path: Path):
    # Pickle/joblib is executable: load only a locally trained, trusted artifact.
    model = joblib.load(path)
    if model.get("version") != 1 or model.get("sklearn") != sklearn.__version__:
        raise ValueError("Model version mismatch. Retrain using the installed scikit-learn version.")
    return model


def predict(bundle, record, allow_demo=False):
    if record.get("is_directory"):
        return {
            "source": "ML unavailable",
            "category": "unknown",
            "decision": "unknown",
            "reason": "File classifier is not applied to directories; use directory aggregates and knowledge context.",
        }
    feat = features(record)
    if bundle["synthetic"] and not allow_demo:
        return {
            "source": "ML unavailable",
            "category": "unknown",
            "decision": "unknown",
            "reason": "Synthetic model is blocked for real recommendations; use --allow-demo only for demonstration.",
        }
    is_supported = supported(record, bundle)
    x = [feat]
    category_probs = bundle["category"].predict_proba(x)[0]
    best = int(np.argmax(category_probs))
    confidence = float(category_probs[best])
    category = str(bundle["category"].classes_[best]) if is_supported and confidence >= 0.8 else "unknown"
    decision = decisions(bundle, [record])[0]
    # Synthetic models never produce actionable cleanup recommendations.
    if bundle["synthetic"] or decision == "safe" and not assess(record, live=True).review_eligible:
        decision = "unknown"
    return {
        "source": "ML prediction, not established fact",
        "model_id": bundle["id"],
        "synthetic_demo_only": bundle["synthetic"],
        "category": category,
        "category_probability_uncalibrated": confidence,
        "supported_feature_context": is_supported,
        "safe_probability_calibrated": float(safe_prob(bundle["safety"], x)[0]),
        "decision": {"safe": "review_candidate", "important": "retain", "unknown": "unknown"}[decision],
        "cleanup_priority_prediction": str(bundle["priority"].predict(x)[0]),
        "policy_threshold": bundle["policy"]["threshold"],
        "features": feat,
        "explanation": "Prediction uses extension, location context, size, age, depth and attributes. "
        "Global importance is not a causal explanation or proof of dispensability.",
    }
