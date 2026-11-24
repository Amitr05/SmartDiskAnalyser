import json

from typer.testing import CliRunner

from disklens.cli import app, resolve_user_path

runner = CliRunner()


def call(tmp_path, *args):
    return runner.invoke(app, ["--db", str(tmp_path / "state.sqlite"), "--format", "json", *map(str, args)])


def test_cli_drives_json(tmp_path):
    result = call(tmp_path, "drives")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "path" in data[0]


def test_cli_drives_terminal(tmp_path):
    res = runner.invoke(app, ["--db", str(tmp_path / "state.sqlite"), "--format", "terminal", "drives"])
    assert res.exit_code == 0, res.output
    assert "Available Drives" in res.output


def test_cli_categories_command(tmp_path, tree):
    call(tmp_path, "scan", tree)
    result = call(tmp_path, "categories")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert "categories" in data
    assert isinstance(data["categories"], list)


def test_cli_tree_command(tmp_path, tree):
    call(tmp_path, "scan", tree)
    result = call(tmp_path, "tree")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert "directories" in data


def test_cli_apps_command(tmp_path, tree):
    call(tmp_path, "scan", tree)
    result = call(tmp_path, "apps")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert "total_installed_apps_registered" in data


def test_cli_styled_html_report(tmp_path, tree):
    call(tmp_path, "scan", tree)
    out_html = tmp_path / "styled_report.html"
    res = runner.invoke(
        app,
        [
            "--db",
            str(tmp_path / "state.sqlite"),
            "--format",
            "html",
            "--output",
            str(out_html),
            "report",
        ],
    )
    assert res.exit_code == 0, res.output
    content = out_html.read_text(encoding="utf-8")
    assert "<!doctype html>" in content
    assert "DiskLens — Storage Intelligence Report" in content
    assert "Total Storage Scanned" in content


def test_cli_scan_all_mocked(monkeypatch, tmp_path, tree):
    from disklens.drives import DriveInfo

    mock_drive = DriveInfo(
        path=str(tree),
        letter="T",
        drive_type="Fixed",
        label="TestTree",
        filesystem="NTFS",
        total_bytes=1000000,
        used_bytes=50000,
        free_bytes=950000,
        percent_used=5.0,
        is_ready=True,
        is_suitable_for_scan=True,
    )
    monkeypatch.setattr("disklens.cli.get_scannable_drives", lambda: [mock_drive])

    result = call(tmp_path, "scan", "--all")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["scan_type"] == "all_drives"
    assert data["drives_scanned"] == 1
    assert data["total_files"] == 3


def test_resolve_user_path(tmp_path):
    from pathlib import Path

    # Existing path resolves directly
    assert resolve_user_path(str(tmp_path)) == tmp_path.resolve()
    # Empty string returns home
    assert resolve_user_path("") == Path.home()
    # None returns home
    assert resolve_user_path(None) == Path.home()

