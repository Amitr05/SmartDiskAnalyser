import json

from typer.testing import CliRunner

from disklens.cli import app

runner = CliRunner()


def call(tmp_path, *args):
    return runner.invoke(app, ["--db", str(tmp_path / "state.sqlite"), "--format", "json", *map(str, args)])


def test_scan_analyze_query_report(tmp_path, tree):
    result = call(tmp_path, "scan", tree)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["file_count"] == 3
    result = call(tmp_path, "analyze")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["scan"]["unique_bytes"] == 129
    for command in [
        ("ask", "largest files"),
        ("largest",),
        ("anomalies",),
        ("duplicates",),
        ("cleanup",),
        ("apps",),
        ("forecast",),
        ("report",),
        ("inspect", tree),
        ("risk", tree),
    ]:
        result = call(tmp_path, *command)
        assert result.exit_code == 0, result.output
        json.loads(result.stdout)


def test_no_scan_helpful_error(tmp_path):
    result = call(tmp_path, "analyze")
    assert result.exit_code == 1 and "No scan found" in result.output


def test_execute_fails_closed_and_preserves_files(tmp_path, tree):
    call(tmp_path, "scan", tree)
    before = {str(p): p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    result = call(tmp_path, "cleanup", "--execute")
    assert result.exit_code == 1 and "disabled" in result.output
    after = {str(p): p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    assert before == after
    result = call(tmp_path, "cleanup", "--no-dry-run")
    assert result.exit_code == 1


def test_output_formats_and_no_overwrite(tmp_path, tree):
    call(tmp_path, "scan", tree)
    for fmt in ("json", "csv", "html"):
        out = tmp_path / f"report.{fmt}"
        args = ["--db", str(tmp_path / "state.sqlite"), "--format", fmt, "--output", str(out), "report"]
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert out.stat().st_size > 100
        again = runner.invoke(app, args)
        assert again.exit_code == 1


def test_csv_formula_neutralized(tmp_path):
    from types import SimpleNamespace

    from disklens.cli import emit

    out = tmp_path / "report.csv"
    emit(SimpleNamespace(obj={"format": "csv", "output": out}), [{"name": "=SUM(1,2)"}])
    assert "'=SUM" in out.read_text()


def test_noninteractive_default_shows_help():
    result = runner.invoke(app, [])
    assert result.exit_code == 0 and "DiskLens" in result.output


def test_protected_never_cleanup_candidate(tmp_path, tree):
    path = tree / "Windows" / "Temp"
    path.mkdir(parents=True)
    (path / "a.tmp").write_bytes(b"temp")
    call(tmp_path, "scan", tree)
    result = call(tmp_path, "cleanup")
    items = json.loads(result.stdout)["review_items"]
    assert not any("Windows" in r["path"] for r in items)


def test_config_exclusions(tmp_path, tree):
    config = tmp_path / "config.toml"
    config.write_text('[disklens]\nexclude = ["Temp"]\n')
    result = runner.invoke(
        app,
        ["--db", str(tmp_path / "x.sqlite"), "--config", str(config), "--format", "json", "scan", str(tree)],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["file_count"] == 1
