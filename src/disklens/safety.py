"""Non-learned safety veto. Unverified dependencies are never treated as absent."""

import ctypes
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .knowledge import location, parts


@dataclass
class Assessment:
    risk: str
    protected: bool
    review_eligible: bool
    reasons: list[str]
    action: str

    def to_dict(self):
        return asdict(self)


def windows_protection(path):
    """Query Windows Resource Protection. Failure means unverified, not unprotected."""
    if os.name != "nt":
        return None
    try:
        api = ctypes.WinDLL("sfc", use_last_error=True).SfcIsFileProtected
        api.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        api.restype = ctypes.c_bool
        return bool(api(None, str(Path(path).absolute())))
    except (OSError, AttributeError):
        return None


def assess(record, live=False):
    path = record["path"]
    extension = record.get("extension", "").lower()
    p = set(parts(path))
    wrp = windows_protection(path) if live else record.get("wrp_protected")
    # Component matching (not unsafe string prefixes); all drive letters supported.
    protected = bool(
        p
        & {
            "windows",
            "system32",
            "syswow64",
            "winsxs",
            "boot",
            "efi",
            "system volume information",
            "$recycle.bin",
            "recovery",
        }
    )
    name = str(path).replace("\\", "/").split("/")[-1].casefold()
    protected |= name in {"bootmgr", "bcd", "ntldr", "pagefile.sys", "hiberfil.sys", "swapfile.sys"}
    # Cover a custom Windows installation directory as well as conventional names.
    for env in ("SystemRoot", "windir"):
        base = os.environ.get(env)
        if base:
            root_parts, file_parts = parts(base), parts(path)
            protected |= file_parts[: len(root_parts)] == root_parts
    if protected or wrp is True or record.get("is_system"):
        return Assessment(
            "CRITICAL",
            True,
            False,
            ["Protected system location, system attribute, or Windows Resource Protection."],
            "DO NOT DELETE. Use supported Windows maintenance tools.",
        )
    if live:
        try:
            actual = Path(path).resolve(strict=True)
            if actual != Path(path).absolute():
                resolved = assess({**record, "path": str(actual)}, live=False)
                if resolved.protected:
                    return resolved
                return Assessment(
                    "HIGH RISK",
                    False,
                    False,
                    ["Path traverses an alias/link or requires normalization."],
                    "Retain.",
                )
        except (OSError, RuntimeError):
            return Assessment("CAUTION", False, False, ["Live path verification failed."], "UNKNOWN: retain.")
    if record.get("is_link") or (not record.get("is_directory") and record.get("nlink", 1) > 1):
        return Assessment("HIGH RISK", False, False, ["Linked/reparse or multiply linked file."], "Retain.")
    if record.get("is_readonly") or p & {"program files", "program files (x86)", "programdata", "roaming"}:
        return Assessment(
            "HIGH RISK",
            False,
            False,
            ["Application state/install location or read-only attribute."],
            "Use supported application maintenance, not manual deletion.",
        )
    if extension in {
        ".dll",
        ".exe",
        ".sys",
        ".db",
        ".sqlite",
        ".vhd",
        ".vhdx",
        ".pem",
        ".key",
        ".kdbx",
        ".dat",
    }:
        return Assessment(
            "HIGH RISK",
            False,
            False,
            ["Executable, persistent data, or sensitive file type."],
            "Investigate dependencies; retain.",
        )
    loc = location(path)
    if loc == "personal" or extension in {
        ".pdf",
        ".docx",
        ".txt",
        ".jpg",
        ".png",
        ".mp4",
        ".zip",
        ".bak",
        ".7z",
        ".csv",
    }:
        return Assessment(
            "USER REVIEW",
            False,
            False,
            ["Potential personal data; metadata cannot prove dispensability."],
            "Owner decides after checking backups and dependencies.",
        )
    if loc in {"temp", "cache"} and not record.get("is_directory"):
        return Assessment(
            "CAUTION",
            False,
            True,
            ["Temporary/cache context only; active use and regeneration are unverified."],
            "Review through the owning application or OS cleanup tool. No deletion authorization.",
        )
    return Assessment(
        "CAUTION",
        False,
        False,
        ["Insufficient evidence; dependency, signature, ownership and usage checks not established."],
        "UNKNOWN: retain pending investigation.",
    )
