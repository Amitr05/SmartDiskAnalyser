import os

import pytest

from disklens.analysis import directories
from disklens.scanner import is_reparse


def test_scan_totals(db, tree):
    result = db.scan(tree)
    assert result["status"] == "complete"
    assert result["file_count"] == 3
    assert result["logical_bytes"] == result["unique_bytes"] == 129
    assert len(list(db.records(result["id"]))) == 3
    totals = {r["path"]: r for r in directories(db, result)}
    assert totals[str(tree)]["bytes"] == 129
    assert totals[str(tree / "Temp")]["bytes"] == 120
    assert len(db.conn.execute("SELECT * FROM storage_history").fetchall()) == 1


def test_exclusions(db, tree):
    result = db.scan(tree, ["Temp"])
    assert result["file_count"] == 1


def test_hardlink_accounting(db, tree):
    try:
        os.link(tree / "Temp" / "a.tmp", tree / "hardlink")
    except OSError:
        pytest.skip("Hardlink creation unsupported or denied in this environment")
    result = db.scan(tree)
    assert result["logical_bytes"] == 189
    assert result["unique_bytes"] == 129


def test_symlink_loop_is_skipped_and_reported(db, tree):
    try:
        (tree / "loop").symlink_to(tree, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    result = db.scan(tree)
    assert result["status"] == "partial"
    assert result["error_count"] == 1
    assert result["file_count"] == 3
    assert not db.conn.execute("SELECT * FROM storage_history").fetchall()


def test_live_db_not_counted(tmp_path):
    from disklens.database import Database

    root = tmp_path / "root"
    root.mkdir()
    (root / "a").write_text("abc")
    state = Database(root / "history.sqlite")
    try:
        result = state.scan(root)
        assert result["file_count"] == 1
    finally:
        state.close()


def test_permission_error_is_explicit(monkeypatch, db, tree):
    original = os.scandir

    def guarded(path):
        if str(path) == str(tree / "Temp"):
            raise PermissionError("fixture denial")
        return original(path)

    monkeypatch.setattr(os, "scandir", guarded)
    result = db.scan(tree)
    assert result["status"] == "partial"
    assert result["error_count"] == 1
    assert result["file_count"] == 1


def test_cancelled_scan_persisted(monkeypatch, db, tree):
    import disklens.database as module

    original = module.walk

    def interrupted(*args):
        yield next(iter(original(*args)))
        raise KeyboardInterrupt

    monkeypatch.setattr(module, "walk", interrupted)
    result = db.scan(tree)
    assert result["status"] == "cancelled"
    assert db.latest()["id"] == result["id"]
    assert not db.conn.execute("SELECT * FROM storage_history").fetchall()


def test_invalid_root(db, tree):
    with pytest.raises(ValueError):
        db.scan(tree / "Temp" / "a.tmp")


def test_reparse_marker():
    class Fake:
        st_file_attributes = 0x400

    assert is_reparse(Fake())


def test_root_link_rejected(db, tree, tmp_path):
    link = tmp_path / "alias"
    try:
        link.symlink_to(tree, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    result = db.scan(link)
    assert result["status"] == "failed"
    assert result["file_count"] == 0
