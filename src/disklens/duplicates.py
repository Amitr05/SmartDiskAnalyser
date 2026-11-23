"""Selective SHA-256, then byte comparison. Names/sizes are never proof of duplication."""

import hashlib
import os
import stat
from collections import defaultdict
from pathlib import Path

from .scanner import is_reparse


def identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def open_regular(path):
    before = Path(path).lstat()
    if not stat.S_ISREG(before.st_mode) or is_reparse(before):
        raise ValueError("Not a regular non-reparse file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    handle = os.fdopen(fd, "rb")
    if identity(os.fstat(handle.fileno())) != identity(before):
        handle.close()
        raise ValueError("File changed while opening")
    return handle, before


def digest(path, expected=None):
    handle, before = open_regular(path)
    if expected and identity(before) != tuple(expected):
        handle.close()
        raise ValueError("File changed since scan")
    with handle:
        h = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise ValueError("File changed during hashing")
    if identity(Path(path).lstat()) != identity(before):
        raise ValueError("Path changed during hashing")
    return h.hexdigest()


def equal(a, b, expected_a=None, expected_b=None, expected_sha=None):
    left, sa = open_regular(a)
    try:
        right, sb = open_regular(b)
        with right:
            if (expected_a is not None and identity(sa) != tuple(expected_a)) or (
                expected_b is not None and identity(sb) != tuple(expected_b)
            ):
                return False
            verified_hash = hashlib.sha256()
            while True:
                ca, cb = left.read(1024 * 1024), right.read(1024 * 1024)
                if ca != cb:
                    return False
                if not ca:
                    break
                verified_hash.update(ca)
            # Timestamp granularity can hide same-size changes between passes.
            # Bind byte verification to the original hash, not metadata alone.
            return (
                (expected_sha is None or verified_hash.hexdigest() == expected_sha)
                and identity(os.fstat(left.fileno())) == identity(sa)
                and identity(os.fstat(right.fileno())) == identity(sb)
                and identity(Path(a).lstat()) == identity(sa)
                and identity(Path(b).lstat()) == identity(sb)
            )
    finally:
        left.close()


def find_duplicates(db, scan_id):
    groups, errors = [], []
    sizes = db.conn.execute(
        """SELECT size FROM files WHERE scan_id=? AND is_directory=0 AND size>0
                              GROUP BY size HAVING COUNT(*)>1""",
        (scan_id,),
    )
    for row in sizes:
        hashes, seen, expected_by_path = defaultdict(list), set(), {}
        for file in db.conn.execute(
            """SELECT metadata FROM files WHERE scan_id=? AND size=?
                                      AND is_directory=0""",
            (scan_id, row[0]),
        ):
            import json

            rec = json.loads(file[0])
            key = rec["device"], rec["inode"]
            if key in seen or rec["nlink"] > 1:
                continue
            seen.add(key)
            try:
                expected = [rec[k] for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")]
                hashes[digest(rec["path"], expected)].append(rec["path"])
                expected_by_path[rec["path"]] = expected
            except (OSError, ValueError) as exc:
                errors.append({"path": rec["path"], "error": str(exc)})
        for sha, paths in hashes.items():
            if len(paths) < 2:
                continue
            verified = [paths[0]]
            for other in paths[1:]:
                try:
                    if equal(paths[0], other, expected_by_path[paths[0]], expected_by_path[other], sha):
                        verified.append(other)
                    else:
                        errors.append({"path": other, "error": "Byte verification failed or file changed"})
                except (OSError, ValueError) as exc:
                    errors.append({"path": other, "error": str(exc)})
            if len(verified) > 1:
                groups.append(
                    {
                        "sha256": sha,
                        "paths": verified,
                        "size_each": row[0],
                        "potential_bytes": row[0] * (len(verified) - 1),
                        "action": "Review copies and dependencies; duplication is not deletion safety.",
                    }
                )
    return {"groups": groups, "errors": errors, "potential_bytes": sum(g["potential_bytes"] for g in groups)}
