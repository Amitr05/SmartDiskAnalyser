from disklens.identification import identify


def test_magic_not_extension(tmp_path):
    file = tmp_path / "not_really_text.txt"
    file.write_bytes(b"SQLite format 3\x00" + b"x" * 100)
    result = identify(file)
    assert result["signature_hint"] == "sqlite_database"
    assert result["bytes_read"] == 32


def test_unrecognized_is_unknown(tmp_path):
    file = tmp_path / "x.bin"
    file.write_bytes(b"hello")
    assert identify(file)["signature_hint"] == "unknown"
