import pytest

from disklens.database import Database


@pytest.fixture
def db(tmp_path):
    state = Database(tmp_path / "state" / "test.sqlite")
    yield state
    state.close()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "fixture"
    (root / "Temp").mkdir(parents=True)
    (root / "Documents").mkdir()
    (root / "Temp" / "a.tmp").write_bytes(b"abc" * 20)
    (root / "Temp" / "b.tmp").write_bytes(b"abc" * 20)
    (root / "Documents" / "personal.txt").write_bytes(b"keep this")
    (root / "empty").mkdir()
    return root
