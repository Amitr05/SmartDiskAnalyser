"""Iterative traversal; no link following, hashing, or file contents during scans."""

import fnmatch
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

from .records import FileRecord


def is_reparse(st):
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)


def metadata(path: Path, root: Path) -> FileRecord:
    st = path.lstat()
    attrs = getattr(st, "st_file_attributes", 0)
    linked = stat.S_ISLNK(st.st_mode) or is_reparse(st)
    # POSIX st_blocks measures physical allocation. Windows is unknown here,
    # not an invented size equal to the logical size.
    allocated = st.st_blocks * 512 if hasattr(st, "st_blocks") else None
    return FileRecord(
        str(path),
        str(path.parent),
        path.name,
        path.suffix.lower(),
        st.st_size,
        allocated,
        st.st_mtime_ns,
        st.st_ctime_ns,
        st.st_atime_ns,
        st.st_dev,
        st.st_ino,
        st.st_nlink,
        len(path.relative_to(root).parts),
        path.name.startswith(".") or bool(attrs & 2),
        bool(attrs & 4),
        bool(attrs & 1),
        linked,
        stat.S_ISDIR(st.st_mode),
    )


def walk(root: Path, exclude=(), on_error: Callable | None = None) -> Iterator[FileRecord]:
    """Stream records. Report every failure. Never traverse reparse points or mounts.

    Directory entries are streamed; the pending stack holds directories, not files.
    Hard-linked regular files are stored as paths but excluded from physical totals
    by the database's (device,inode) accounting.
    """
    root = root.absolute()
    root_st = root.lstat()
    if root.is_symlink() or is_reparse(root_st):
        raise ValueError("Scan root cannot be a symlink/junction/reparse point")
    for ancestor in root.parents:
        if ancestor.is_symlink() or is_reparse(ancestor.lstat()):
            raise ValueError("Scan root cannot traverse a symlink/junction/reparse point")
    if not root.is_dir():
        raise ValueError("Scan root must be a directory")
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            current_st = directory.lstat()
            if stat.S_ISLNK(current_st.st_mode) or is_reparse(current_st):
                if on_error:
                    on_error(str(directory), "directory changed to link/reparse point")
                continue
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    rel = path.relative_to(root).as_posix()
                    if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(entry.name, p) for p in exclude):
                        continue
                    try:
                        rec = metadata(path, root)
                        if rec.device != root_st.st_dev:
                            if on_error:
                                on_error(str(path), "mount boundary not traversed")
                            continue
                        if rec.is_link:
                            if on_error:
                                on_error(str(path), "link/reparse point skipped")
                            continue
                        if rec.is_directory:
                            pending.append(path)
                        elif not stat.S_ISREG(path.lstat().st_mode):
                            if on_error:
                                on_error(str(path), "special file skipped")
                            continue
                        yield rec
                    except OSError as exc:
                        if on_error:
                            on_error(str(path), str(exc))
        except OSError as exc:
            if on_error:
                on_error(str(directory), str(exc))
