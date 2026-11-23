"""Opt-in bounded header inspection. A recognizable format is not deletion evidence."""

from .duplicates import identity, open_regular

SIGNATURES = (
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"PK\x03\x04", "zip_container"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"MZ", "windows_executable_container"),
    (b"\x7fELF", "elf_executable"),
    (b"SQLite format 3\x00", "sqlite_database"),
)


def identify(path):
    import os

    handle, before = open_regular(path)
    with handle:
        header = handle.read(32)
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("File changed during header inspection")
    detected = next((name for prefix, name in SIGNATURES if header.startswith(prefix)), "unknown")
    return {
        "signature_hint": detected,
        "bytes_read": len(header),
        "source": "bounded magic-byte inspection, not a full format parser",
        "warning": "Headers can be spoofed. Unknown is not evidence of dispensability.",
    }
