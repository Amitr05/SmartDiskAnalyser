"""Serializable scanner facts. None means unverified, never false."""

from dataclasses import asdict, dataclass


@dataclass
class FileRecord:
    path: str
    parent: str
    name: str
    extension: str
    size: int
    allocated: int | None
    mtime_ns: int
    ctime_ns: int
    atime_ns: int
    device: int
    inode: int
    nlink: int
    depth: int
    is_hidden: bool
    is_system: bool
    is_readonly: bool
    is_link: bool
    is_directory: bool = False
    wrp_protected: bool | None = None
    signed: bool | None = None

    def to_dict(self):
        return asdict(self)
