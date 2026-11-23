"""Windows and cross-platform drive discovery, volume inspection, and capacity measurement."""

import ctypes
import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

DRIVE_TYPES = {
    0: "Unknown",
    1: "No Root Directory",
    2: "Removable",
    3: "Fixed",
    4: "Network",
    5: "CD-ROM",
    6: "RAMDisk",
}


@dataclass
class DriveInfo:
    path: str
    letter: str
    drive_type: str
    label: str
    filesystem: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent_used: float
    is_ready: bool
    is_suitable_for_scan: bool
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _get_windows_drives() -> list[DriveInfo]:
    kernel32 = ctypes.windll.kernel32
    bitmask = kernel32.GetLogicalDrives()
    drives: list[DriveInfo] = []

    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        letter = chr(ord("A") + i)
        root_path = f"{letter}:\\"
        dtype_code = kernel32.GetDriveTypeW(root_path)
        dtype_name = DRIVE_TYPES.get(dtype_code, "Unknown")

        label = ""
        fs_type = ""
        total_b = 0
        used_b = 0
        free_b = 0
        percent = 0.0
        is_ready = False
        error_msg = None

        # Ignore CD-ROM and non-existent roots for storage querying
        if dtype_code == 5:
            # CD-ROM
            drives.append(
                DriveInfo(
                    path=root_path,
                    letter=letter,
                    drive_type=dtype_name,
                    label="",
                    filesystem="",
                    total_bytes=0,
                    used_bytes=0,
                    free_bytes=0,
                    percent_used=0.0,
                    is_ready=False,
                    is_suitable_for_scan=False,
                    error="Optical disc drive",
                )
            )
            continue

        try:
            vol_buf = ctypes.create_unicode_buffer(260)
            fs_buf = ctypes.create_unicode_buffer(260)
            success = kernel32.GetVolumeInformationW(
                root_path, vol_buf, 260, None, None, None, fs_buf, 260
            )
            if success:
                label = vol_buf.value
                fs_type = fs_buf.value

            usage = shutil.disk_usage(root_path)
            total_b = usage.total
            free_b = usage.free
            used_b = usage.used
            percent = (used_b / total_b * 100.0) if total_b > 0 else 0.0
            is_ready = True
        except (OSError, PermissionError) as exc:
            is_ready = False
            error_msg = str(exc)

        # Suitable for automated scanning: ready Fixed or Removable drives
        is_suitable = is_ready and dtype_code in (2, 3) and total_b > 0

        drives.append(
            DriveInfo(
                path=root_path,
                letter=letter,
                drive_type=dtype_name,
                label=label,
                filesystem=fs_type,
                total_bytes=total_b,
                used_bytes=used_b,
                free_bytes=free_b,
                percent_used=round(percent, 1),
                is_ready=is_ready,
                is_suitable_for_scan=is_suitable,
                error=error_msg,
            )
        )

    return drives


def _get_posix_drives() -> list[DriveInfo]:
    drives: list[DriveInfo] = []
    candidates = ["/"]
    home = str(Path.home())
    if home not in candidates:
        candidates.append(home)

    # Check /media or /mnt if present
    for mount_dir in ("/media", "/mnt"):
        p = Path(mount_dir)
        if p.exists() and p.is_dir():
            try:
                for child in p.iterdir():
                    if child.is_dir() and not child.is_symlink():
                        candidates.append(str(child))
            except OSError:
                pass

    seen = set()
    for root in candidates:
        if root in seen:
            continue
        seen.add(root)
        try:
            usage = shutil.disk_usage(root)
            percent = (usage.used / usage.total * 100.0) if usage.total > 0 else 0.0
            drives.append(
                DriveInfo(
                    path=root,
                    letter=root,
                    drive_type="Fixed" if root == "/" else "Mount",
                    label=Path(root).name or "root",
                    filesystem="",
                    total_bytes=usage.total,
                    used_bytes=usage.used,
                    free_bytes=usage.free,
                    percent_used=round(percent, 1),
                    is_ready=True,
                    is_suitable_for_scan=True,
                    error=None,
                )
            )
        except OSError as exc:
            drives.append(
                DriveInfo(
                    path=root,
                    letter=root,
                    drive_type="Mount",
                    label=Path(root).name or root,
                    filesystem="",
                    total_bytes=0,
                    used_bytes=0,
                    free_bytes=0,
                    percent_used=0.0,
                    is_ready=False,
                    is_suitable_for_scan=False,
                    error=str(exc),
                )
            )

    return drives


def get_available_drives() -> list[DriveInfo]:
    """Return all detected drives / mounted volumes."""
    if os.name == "nt":
        return _get_windows_drives()
    return _get_posix_drives()


def get_scannable_drives() -> list[DriveInfo]:
    """Return only active, accessible drives suitable for full analysis."""
    return [d for d in get_available_drives() if d.is_suitable_for_scan]
