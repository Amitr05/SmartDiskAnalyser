import time

import pytest

from disklens.analysis import anomalies, applications, compare, forecast
from disklens.query import answer, intent


def test_forecast_refuses_single_scan(db, tree):
    current = db.scan(tree)
    assert forecast(db, current["root"])["status"] == "insufficient_history"


def test_forecast_real_history_temporal_backtest(db):
    now = time.time() - 20 * 86400
    for i in range(8):
        db.conn.execute(
            "INSERT INTO storage_history VALUES(?,?,?,?)",
            (str(i), "/fixture", now + i * 2 * 86400, 1000 + i * 200),
        )
    db.conn.commit()
    result = forecast(db, "/fixture", capacity=5000)
    assert result["status"] == "ok"
    assert result["daily_growth_bytes"] == pytest.approx(100)
    assert result["forecast"][0]["predicted_bytes"] == 3100
    assert result["estimated_days_to_scope_capacity"] == pytest.approx(26)
    assert result["temporal_mae_bytes"] == pytest.approx(0, abs=1e-7)


def test_multiple_same_day_scans_not_history(db):
    now = time.time()
    for i in range(8):
        db.conn.execute("INSERT INTO storage_history VALUES(?,?,?,?)", (str(i), "/x", now, 10 + i))
    assert forecast(db, "/x")["status"] == "insufficient_history"


def test_anomalies_insufficient(db, tree):
    scan = db.scan(tree)
    assert anomalies(db, scan)["status"] == "insufficient_data"


def test_anomalies_trains_on_directories(db, tree):
    for i in range(20):
        path = tree / str(i)
        path.mkdir()
        (path / "data").write_bytes(b"a" * (10 if i < 19 else 100000))
    scan = db.scan(tree)
    result = anomalies(db, scan)
    assert result["status"] == "ok"
    assert result["directories_observed"] >= 20
    assert result["results"]


def test_compare_changes(db, tree):
    first = db.scan(tree)
    (tree / "new.bin").write_bytes(b"new")
    (tree / "Documents" / "personal.txt").unlink()
    (tree / "Temp" / "a.tmp").write_bytes(b"changed")
    second = db.scan(tree)
    result = compare(db, first["id"], second["id"])
    assert result["added"] == 1 and result["removed"] == 1
    assert result["changed_first_50"][0]["delta_bytes"] == -53


def test_application_hints(db, tree):
    path = tree / "node_modules"
    path.mkdir()
    (path / "module.js").write_text("content")
    result = applications(db, db.scan(tree))
    assert result["applications"][0]["name"] == "Node dependencies / npm"


@pytest.mark.parametrize(
    "question,expected",
    [
        ("What are my largest files?", "largest"),
        ("Find duplicate downloads", "duplicates"),
        ("How much storage will I use in the future?", "forecast"),
        ("Is it safe to delete this?", "safety"),
        ("Show unusual folders", "anomalies"),
        ("Show application storage", "applications"),
        ("Storage breakdown", "summary"),
        ("Tell me a joke", "unknown"),
    ],
)
def test_query_intents(question, expected):
    assert intent(question) == expected


def test_query_grounded_in_scan(db, tree):
    scan = db.scan(tree)
    response = answer(db, scan, "largest files")
    assert response["scan_id"] == scan["id"]
    assert response["result"][0]["size"] == 60
    assert response["query_seconds"] >= 0


def test_different_exclusions_cannot_be_compared(db, tree):
    a = db.scan(tree)
    b = db.scan(tree, ["Temp"])
    with pytest.raises(ValueError, match="exclusions"):
        compare(db, a["id"], b["id"])


def test_benchmark_records_measured_latency(db, tree, tmp_path):
    import json

    from disklens.benchmark import benchmark

    cases = tmp_path / "questions.jsonl"
    cases.write_text(json.dumps({"question": "largest files", "expected_intent": "largest"}) + "\n")
    result = benchmark(db, tree, cases, repeats=2)
    assert result["intent_accuracy"] == 1
    assert result["scan_latency"]["n"] == 2
    assert result["query_latency"]["median_seconds"] >= 0
