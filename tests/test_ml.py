import json

import pytest

from disklens.ml.data import demo_dataset, reconcile, validate
from disklens.ml.features import features
from disklens.ml.policy import choose_threshold, metrics, wilson_upper
from disklens.ml.training import decisions, load_model, predict, train


def test_features_exclude_identity_and_labels():
    row = demo_dataset(30)[0]
    f = features(row)
    assert "label" not in f and "device_id" not in f and "path" not in f
    assert set(f) == {
        "extension",
        "location",
        "log_size",
        "modified_days",
        "depth",
        "hidden",
        "system",
        "readonly",
        "linked",
    }


@pytest.mark.parametrize("field", ["device_id", "user_id", "sha256", "related_group"])
def test_cross_split_leakage_rejected(field):
    rows = demo_dataset(30)
    rows[-1][field] = rows[0][field]
    with pytest.raises(ValueError, match="Leakage"):
        validate(rows)


def test_annotations_agreement_and_unknown_resolution():
    a = [
        {"record_id": "a", "label": "safe", "annotator_id": "one", "evidence": "owner-confirmed"},
        {"record_id": "b", "label": "important", "annotator_id": "one", "evidence": "only copy"},
    ]
    b = [
        {"record_id": "a", "label": "safe", "annotator_id": "two", "evidence": "regenerable"},
        {"record_id": "b", "label": "safe", "annotator_id": "two", "evidence": "old"},
    ]
    result = reconcile(a, b)
    assert result["agreement"] == 0.5
    assert result["resolved"][1]["label"] == "unknown"
    assert result["cohen_kappa"] == 0.0
    result = reconcile(
        a,
        b,
        [
            {
                "record_id": "b",
                "label": "important",
                "annotator_id": "third",
                "evidence": "owner verified no backup",
            }
        ],
    )
    assert result["resolved"][1]["label"] == "important"


def test_annotator_cannot_agree_with_self():
    a = [{"record_id": "a", "label": "safe", "annotator_id": "one", "evidence": "x"}]
    with pytest.raises(ValueError):
        reconcile(a, a)


def test_threshold_abstains_on_insufficient_evidence():
    result = choose_threshold([0.999] * 20, ["safe"] * 20, list(range(20)), [True] * 20)
    assert result["threshold"] is None
    assert wilson_upper(0, 0) == 1


def test_threshold_accepts_only_with_enough_group_evidence():
    result = choose_threshold(
        [0.999] * 1000, ["safe"] * 1000, list(range(1000)), [True] * 1000, max_risk=0.02
    )
    assert result["threshold"] == 0.5


def test_duplicates_do_not_inflate_policy_sample_size():
    result = choose_threshold([0.999] * 1000, ["safe"] * 1000, ["one-group"] * 1000, [True] * 1000)
    assert result["threshold"] is None
    assert result["diagnostics"][0]["groups"] == 1


def test_metrics_denominators():
    result = metrics(["safe", "important", "unknown", "important"], ["safe", "safe", "safe", "unknown"])
    assert result["safe_precision"] == 1 / 3
    assert result["false_safe_rate"] == 0.5
    assert result["abstention_rate"] == 0.25
    assert result["unknown_recommended"] == 1
    assert metrics(["important"], ["unknown"])["safe_precision"] is None


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    rows = demo_dataset(90)
    path = tmp_path_factory.mktemp("model")
    report = train(rows, path)
    return load_model(path / "model.joblib"), report, rows


def test_real_training_persistence_and_baselines(trained):
    bundle, report, _rows = trained
    assert report["synthetic_demo_only"]
    assert report["split_counts"]["test"] == 90
    assert "risk_aware" in report["experiments"]
    assert "fixed_rules" in report["experiments"]
    assert "decision_tree" in report["experiments"]
    assert "no_controls" in report["experiments"]
    assert bundle["policy"]["threshold"] is None
    json.dumps(report, allow_nan=False)


def test_synthetic_predictions_cannot_recommend(trained):
    bundle, _, rows = trained
    assert predict(bundle, rows[0])["decision"] == "unknown"
    assert predict(bundle, rows[0], allow_demo=True)["decision"] == "unknown"


def test_protected_veto_even_when_threshold_zero(trained):
    bundle, _, rows = trained
    altered = {**bundle, "policy": {"threshold": 0}}
    protected = {**rows[0], "is_system": True}
    assert decisions(altered, [protected])[0] != "safe"
    assert decisions(altered, [protected], veto=False)[0] == "safe"


def test_unsupported_extension_abstains(trained):
    bundle, _, rows = trained
    altered = {**bundle, "policy": {"threshold": 0}}
    unknown = {**rows[0], "extension": ".completelynew"}
    assert decisions(altered, [unknown])[0] != "safe"


def test_live_wrp_vetoes_even_policy_approved_prediction(monkeypatch, trained, tmp_path):
    from disklens.scanner import metadata

    bundle, _, _ = trained
    altered = {**bundle, "synthetic": False, "policy": {"threshold": 0}}
    root = tmp_path / "Temp"
    root.mkdir()
    path = root / "a.tmp"
    path.write_bytes(b"x")
    rec = metadata(path, tmp_path).to_dict()
    assert decisions(altered, [rec])[0] == "safe"
    monkeypatch.setattr("disklens.safety.windows_protection", lambda _: True)
    assert predict(altered, rec)["decision"] == "unknown"


def test_directory_not_classified_as_file(trained):
    bundle, _, rows = trained
    assert predict(bundle, {**rows[0], "is_directory": True})["category"] == "unknown"


@pytest.mark.parametrize("value", [None, "", "invalid"])
def test_invalid_content_hash_rejected(value):
    rows = demo_dataset(30)
    rows[0]["sha256"] = value
    with pytest.raises(ValueError, match="SHA-256"):
        validate(rows)


def test_bad_numeric_feature_rejected():
    rows = demo_dataset(30)
    rows[0]["modified_days"] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        validate(rows)
