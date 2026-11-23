import pytest

from disklens.safety import assess


def record(path, **extra):
    return {"path": path, "extension": "." + path.rsplit(".", 1)[-1], "size": 10, "nlink": 1, **extra}


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Windows\System32\test.tmp",
        r"D:\WINDOWS\WinSxS\cache.log",
        r"E:\boot\BCD",
        r"C:\EFI\boot\bootx64.efi",
        r"C:\pagefile.sys",
        r"C:\System Volume Information\file",
        r"C:\Recovery\image.wim",
    ],
)
def test_protected_locations(path):
    result = assess(record(path))
    assert result.risk == "CRITICAL"
    assert result.protected and not result.review_eligible


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Program Files\App\Temp\x.tmp",
        r"C:\ProgramData\x.log",
        r"C:\Users\Me\AppData\Roaming\x.tmp",
        r"C:\Temp\state.db",
        r"C:\Temp\app.dll",
    ],
)
def test_high_risk(path):
    result = assess(record(path))
    assert result.risk == "HIGH RISK" and not result.review_eligible


def test_unknown_not_disposable():
    assert not assess(record(r"C:\Mystery\unrecognized.bin")).review_eligible


def test_cache_not_authorized():
    result = assess(record(r"C:\Users\Me\AppData\Local\Cache\a.cache"))
    assert result.risk == "CAUTION" and result.review_eligible
    assert "No deletion authorization" in result.action


def test_personal_inside_temp_still_user_review():
    result = assess(record(r"C:\Temp\thesis.pdf"))
    assert result.risk == "USER REVIEW" and not result.review_eligible


def test_wrp_overrides_all():
    assert assess(record(r"C:\Temp\a.tmp", wrp_protected=True)).risk == "CRITICAL"


def test_system_attribute_overrides_all():
    assert assess(record(r"C:\Temp\a.tmp", is_system=True)).risk == "CRITICAL"


def test_lookalike_component_is_not_system():
    assert not assess(record(r"C:\WindowsBackup\temp\a.tmp")).protected


def test_custom_systemroot(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"Z:\CustomOS")
    assert assess(record(r"Z:\CustomOS\cache\a.tmp")).protected


@pytest.mark.parametrize("extra", [{"nlink": 2}, {"is_link": True}, {"is_readonly": True}])
def test_links_and_attributes_veto(extra):
    assert not assess(record(r"C:\Temp\a.tmp", **extra)).review_eligible


def test_live_protection_called(monkeypatch):
    monkeypatch.setattr("disklens.safety.windows_protection", lambda _: True)
    assert assess(record(r"C:\Temp\a.tmp"), live=True).protected


def test_parent_alias_not_review_eligible(tmp_path):
    root = tmp_path / "real"
    (root / "Temp").mkdir(parents=True)
    (root / "Temp" / "a.tmp").write_bytes(b"active")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink privilege unavailable")
    assert not assess(record(str(alias / "Temp" / "a.tmp")), live=True).review_eligible


def test_posix_directory_link_count_is_not_a_hardlink_warning():
    result = assess(record("/home/example/unfamiliar", is_directory=True, nlink=4))
    assert result.risk == "CAUTION"
    assert not result.review_eligible
