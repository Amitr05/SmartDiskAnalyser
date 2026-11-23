"""Small curated offline knowledge base, not assertions about arbitrary files."""

from pathlib import PureWindowsPath

KB = {
    "windows": (
        "Operating system",
        "Windows components, servicing and system resources.",
        "Do not remove manually. Use supported Windows maintenance tools.",
    ),
    "winsxs": (
        "Windows component store",
        "Components needed for updates, repair and optional features.",
        "Manual removal can prevent servicing and recovery.",
    ),
    "system32": (
        "Windows system directory",
        "System libraries, drivers and executables.",
        "Deleting contents can prevent boot or application execution.",
    ),
    "program files": (
        "Application installations",
        "Installed binaries and shared dependencies.",
        "Use the application uninstaller; manual removal may break applications.",
    ),
    "program files (x86)": (
        "Application installations",
        "Installed 32-bit applications and dependencies.",
        "Use supported uninstallers.",
    ),
    "programdata": (
        "Shared application data",
        "Machine-wide settings, databases and resources.",
        "Do not delete wholesale; data may be persistent.",
    ),
    "appdata": (
        "Mixed application data",
        "Caches alongside settings, databases and user state.",
        "Do not delete the whole directory; prefer application cleanup.",
    ),
    "roaming": (
        "Roaming application data",
        "Application settings and potentially irreplaceable state.",
        "Removing it can reset applications or lose data.",
    ),
    "local": (
        "Local application data",
        "Local databases, caches and downloaded application resources.",
        "Location alone does not establish dispensability.",
    ),
    "temp": (
        "Temporary workspace",
        "Applications may store active sessions, installers or temporary data.",
        "Use application/OS cleanup; age alone is insufficient to prove safe deletion.",
    ),
    "downloads": (
        "User downloads",
        "User-selected downloads, possibly the only copy.",
        "User review required; installers and archives may be irreplaceable.",
    ),
    "users": ("User profiles", "Personal files, settings and application state.", "Never remove wholesale."),
    "node_modules": (
        "Node dependencies",
        "Installed project dependencies, potentially locally modified.",
        "Check lockfiles and local changes before recreating through a package manager.",
    ),
    ".venv": (
        "Python environment",
        "Interpreter and installed project dependencies.",
        "Check reproducibility and local modifications before recreating.",
    ),
    "docker": (
        "Docker-related storage",
        "Images, containers, or persistent volumes may be present.",
        "Inspect using Docker tools. Volumes may contain persistent databases; never delete blindly.",
    ),
    ".gradle": (
        "Gradle storage",
        "Build resources, caches and configuration.",
        "Use Gradle-supported maintenance; preserve configuration and offline dependencies.",
    ),
    ".m2": (
        "Maven storage",
        "Artifacts and repository configuration.",
        "Locally built artifacts may not be recoverable from a remote repository.",
    ),
}


def parts(path):
    return tuple(p.casefold() for p in PureWindowsPath(str(path).replace("/", "\\")).parts)


def explain(path):
    for part in reversed(parts(path)):
        if part in KB:
            title, purpose, consequence = KB[part]
            return {
                "source": "curated knowledge base (directory context, not proof of file purpose)",
                "context": part,
                "title": title,
                "purpose": purpose,
                "consequences": consequence,
            }
    return {
        "source": "unknown",
        "title": "Unrecognized location",
        "purpose": "Not established from available evidence.",
        "consequences": "Dependencies and deletion consequences are unknown. Retain pending review.",
    }


def location(path):
    p = set(parts(path))
    if p & {"windows", "system32", "winsxs", "boot", "efi"}:
        return "system"
    if p & {"program files", "program files (x86)", "programdata", "roaming"}:
        return "application"
    if p & {"temp", "tmp"}:
        return "temp"
    if p & {"cache", "caches", ".cache", "_cacache"}:
        return "cache"
    if p & {"node_modules", ".venv", "venv", ".gradle", ".m2", "sdk", "docker"}:
        return "development"
    if p & {"documents", "downloads", "pictures", "videos", "desktop", "backups"}:
        return "personal"
    return "unknown"


def category_rule(record):
    loc = location(record["path"])
    ext = record["extension"]
    if loc == "system":
        return "operating_system"
    if ext in {".doc", ".docx", ".pdf", ".txt", ".odt", ".xlsx"}:
        return "document"
    if ext in {".mp4", ".mp3", ".png", ".jpg", ".jpeg", ".wav", ".mkv"}:
        return "media"
    if ext in {".zip", ".7z", ".tar", ".gz", ".bak"}:
        return "archive"
    if ext in {".msi", ".msix"}:
        return "installer"
    if ext in {".db", ".sqlite", ".ini", ".yaml", ".toml", ".json", ".dll", ".exe", ".sys"}:
        return "application"
    if ext == ".log":
        return "log"
    return {
        "temp": "temporary",
        "cache": "cache",
        "development": "development",
        "application": "application",
    }.get(loc, "unknown")
