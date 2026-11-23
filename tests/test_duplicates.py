import os

import pytest

from disklens.duplicates import digest, find_duplicates


def test_duplicates_verified(db, tree):
    scan = db.scan(tree)
    result = find_duplicates(db, scan["id"])
    assert len(result["groups"]) == 1
    assert result["potential_bytes"] == 60
    assert not result["errors"]


def test_same_size_not_duplicate(db, tree):
    (tree / "Temp" / "b.tmp").write_bytes(b"xyz" * 20)
    scan = db.scan(tree)
    assert not find_duplicates(db, scan["id"])["groups"]


def test_stale_file_reported(db, tree):
    scan = db.scan(tree)
    (tree / "Temp" / "b.tmp").write_bytes(b"xyz")
    result = find_duplicates(db, scan["id"])
    assert not result["groups"]
    assert result["errors"]


def test_hardlinks_not_reclaimable_duplicates(db, tree):
    try:
        os.link(tree / "Temp" / "a.tmp", tree / "hardlink")
    except OSError:
        pytest.skip("Hardlink creation unsupported or denied in this environment")
    scan = db.scan(tree)
    assert not find_duplicates(db, scan["id"])["groups"]


def test_regular_hash(tree):
    assert digest(tree / "Temp" / "a.tmp") == digest(tree / "Temp" / "b.tmp")


def test_change_between_hash_and_byte_verification_is_rejected(monkeypatch, db, tree):
    import disklens.duplicates as module

    original = module.digest
    scan = db.scan(tree)
    calls = 0

    def change_after_hash(path, expected=None):
        nonlocal calls
        sha = original(path, expected)
        calls += 1
        if calls == 2:
            (tree / "Temp" / "a.tmp").write_bytes(b"xyz" * 20)
            (tree / "Temp" / "b.tmp").write_bytes(b"xyz" * 20)
        return sha

    monkeypatch.setattr(module, "digest", change_after_hash)
    result = module.find_duplicates(db, scan["id"])
    assert not result["groups"]
    assert result["errors"]
