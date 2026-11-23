"""Windows Registry application inventory and grounded filesystem association."""

import os
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any

from .knowledge import parts

# Developer and runtime tool footprints for inferred environment analysis
TOOL_ECOSYSTEMS = {
    "Docker Desktop & Storage": {
        "tokens": {"docker"},
        "category": "Containerization",
        "description": "Docker images, containers, persistent volumes, and build cache.",
    },
    "Node.js / npm Environment": {
        "tokens": {"node_modules", "npm", "_cacache", "npm-cache", "yarn", "pnpm"},
        "category": "JavaScript / Node Runtime",
        "description": "JavaScript package dependencies, package tarball caches, and npm caches.",
    },
    "Python Virtualenvs & Caches": {
        "tokens": {".venv", "venv", "__pycache__", "pip", "site-packages", ".pytest_cache"},
        "category": "Python Runtime",
        "description": "Python isolated environments, compiled bytecode, and pip package caches.",
    },
    "Java / Maven / Gradle Tools": {
        "tokens": {".gradle", ".m2", "jdk", "jre", ".jdks"},
        "category": "Java Ecosystem",
        "description": "Gradle build caches, wrapper distributions, and Maven local repository jars.",
    },
    "Visual Studio Code Environment": {
        "tokens": {"code", ".vscode"},
        "category": "Developer Tooling",
        "description": "VS Code extensions, language server caches, and editor configurations.",
    },
    "Git Version Control": {
        "tokens": {".git", ".github"},
        "category": "Version Control",
        "description": "Git repository histories, packfiles, objects, and local branches.",
    },
    "Steam & PC Games": {
        "tokens": {"steam", "steamapps", "shadercache", "epic games", "riot games"},
        "category": "Gaming",
        "description": "Steam game depots, shaders, download staging, and game assets.",
    },
    "Android SDK & Studio": {
        "tokens": {"android", "sdk", ".android"},
        "category": "Mobile Development",
        "description": "Android SDK platform tools, system images, and build toolchains.",
    },
    "WSL Linux Environment": {
        "tokens": {"wsl", "lxss", "wsl$"},
        "category": "Linux Subsystem",
        "description": "Windows Subsystem for Linux distributions and virtual disks.",
    },
}


@dataclass
class InstalledApp:
    name: str
    version: str
    publisher: str
    install_location: str
    source: str
    is_confirmed: bool

    def to_dict(self):
        return asdict(self)


def get_registry_installed_apps() -> list[InstalledApp]:
    """Query the Windows Registry for installed software across 64-bit, 32-bit, and user hives."""
    if os.name != "nt":
        return []

    import winreg

    apps: list[InstalledApp] = []
    seen_names = set()

    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, subkey_path in hives:
        try:
            with winreg.OpenKey(hive, subkey_path) as root_key:
                num_subkeys = winreg.QueryInfoKey(root_key)[0]
                for i in range(num_subkeys):
                    try:
                        app_guid = winreg.EnumKey(root_key, i)
                        with winreg.OpenKey(root_key, app_guid) as app_key:
                            # Retrieve DisplayName (required)
                            try:
                                name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                if not name or not str(name).strip():
                                    continue
                                name = str(name).strip()
                            except OSError:
                                continue

                            # De-duplicate by name
                            key_lower = name.lower()
                            if key_lower in seen_names:
                                continue
                            seen_names.add(key_lower)

                            # Optional metadata
                            version = ""
                            publisher = ""
                            location = ""

                            try:
                                v, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                version = str(v).strip()
                            except OSError:
                                pass

                            try:
                                p, _ = winreg.QueryValueEx(app_key, "Publisher")
                                publisher = str(p).strip()
                            except OSError:
                                pass

                            try:
                                loc, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                                location = str(loc).strip()
                            except OSError:
                                pass

                            apps.append(
                                InstalledApp(
                                    name=name,
                                    version=version,
                                    publisher=publisher,
                                    install_location=location,
                                    source="Windows Registry",
                                    is_confirmed=bool(location),
                                )
                            )
                    except OSError:
                        continue
        except OSError:
            continue

    return sorted(apps, key=lambda a: a.name.lower())


def analyze_application_storage(db, scan: dict[str, Any]) -> dict[str, Any]:
    """Correlate scanned files with confirmed Windows Registry apps and inferred dev environments."""
    registry_apps = get_registry_installed_apps()

    # Pre-index registry apps with non-empty install locations
    installed_by_prefix = []
    for app in registry_apps:
        if app.install_location and len(app.install_location) > 3:
            norm_loc = app.install_location.replace("\\", "/").rstrip("/").lower()
            installed_by_prefix.append((norm_loc, app))

    confirmed_matches: dict[str, dict[str, Any]] = {}
    inferred_matches: dict[str, dict[str, Any]] = defaultdict(lambda: {"bytes": 0, "files": 0, "paths": set()})

    for rec in db.records(scan["id"]):
        path_str = rec["path"].replace("\\", "/")
        path_lower = path_str.lower()
        size = rec["size"] or 0

        # 1. Check confirmed Windows Registry install locations
        matched_registry = False
        for prefix, app in installed_by_prefix:
            if path_lower.startswith(prefix):
                if app.name not in confirmed_matches:
                    confirmed_matches[app.name] = {
                        "name": app.name,
                        "version": app.version,
                        "publisher": app.publisher,
                        "install_location": app.install_location,
                        "bytes": 0,
                        "files": 0,
                        "identification": "confirmed (Windows Registry)",
                    }
                confirmed_matches[app.name]["bytes"] += size
                confirmed_matches[app.name]["files"] += 1
                matched_registry = True
                break

        if matched_registry:
            continue

        # 2. Check inferred developer environments & tool ecosystems
        p_tokens = set(parts(rec["path"]))
        for ecosystem_name, info in TOOL_ECOSYSTEMS.items():
            if p_tokens & info["tokens"]:
                inferred_matches[ecosystem_name]["bytes"] += size
                inferred_matches[ecosystem_name]["files"] += 1
                inferred_matches[ecosystem_name]["category"] = info["category"]
                inferred_matches[ecosystem_name]["description"] = info["description"]
                break

    confirmed_list = sorted(confirmed_matches.values(), key=lambda r: -r["bytes"])
    inferred_list = [
        {"name": k, "identification": "inferred (directory signature)", **v}
        for k, v in sorted(inferred_matches.items(), key=lambda pair: -pair[1]["bytes"])
        if v["bytes"] > 0
    ]

    return {
        "scan_id": scan["id"],
        "root": scan["root"],
        "confirmed_registry_apps": confirmed_list,
        "inferred_environments": inferred_list,
        "total_installed_apps_registered": len(registry_apps),
    }
