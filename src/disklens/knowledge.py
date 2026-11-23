"""Curated offline filesystem knowledge base, explaining Windows, application, and developer locations."""

from pathlib import Path, PureWindowsPath
from typing import Any

# Comprehensive knowledge entries covering Windows system, applications, and developer tools
# Format: (title, owner, purpose, importance, recreatable, consequences, recommendation)
KB_ENTRIES = {
    # Windows Operating System Core
    "windows": (
        "Windows Operating System Directory",
        "Microsoft Windows",
        "Core operating system binaries, drivers, fonts, system configurations, and servicing resources.",
        "Critical — required for Windows execution and boot.",
        "Cannot be recreated without OS reinstallation or repair.",
        "Manual removal causes immediate system corruption, application failures, or unbootable Windows.",
        "Never delete manually. Use Windows Settings > System > Storage or Disk Cleanup (cleanmgr).",
    ),
    "system32": (
        "Windows 64-bit System Directory",
        "Microsoft Windows Kernel & Subsystems",
        "Contains Windows core executables, essential DLLs, hardware drivers, and system services.",
        "Critical — essential for operating system boot and execution.",
        "Cannot be recreated manually.",
        "System will immediately crash, fail to boot, or refuse to run any executables.",
        "Do not modify or delete. Protected by Windows Resource Protection.",
    ),
    "syswow64": (
        "Windows 32-bit Subsystem on 64-bit Windows",
        "Microsoft Windows 32-bit Compatibility Layer",
        "Libraries and binaries supporting 32-bit application compatibility on 64-bit Windows.",
        "Critical — required for running 32-bit applications.",
        "Cannot be recreated manually.",
        "Breaks all 32-bit applications, installers, and background services.",
        "Do not delete. Managed by Windows Update and servicing.",
    ),
    "winsxs": (
        "Windows Component Store",
        "Windows Servicing & Update Subsystem",
        "Stores multiple assembly versions of system components for updates, role additions, and rollback.",
        "Critical — necessary for OS servicing, update installation, and SFC system repairs.",
        "Cannot be recreated manually; files are hard-linked to System32.",
        "Deleting contents breaks Windows Update, system repair, and component installation.",
        "Use 'Dism.exe /Online /Cleanup-Image /StartComponentCleanup' or Windows Disk Cleanup.",
    ),
    "softwaredistribution": (
        "Windows Update Download Cache",
        "Windows Update Service (wuauserv)",
        "Temporary staging directory where Windows Update downloads update patches and manifests.",
        "Low to Medium — temporary staging files for pending/installed Windows updates.",
        "Yes, automatically re-downloaded if updates are pending.",
        "Safe to reset if Windows Update is stuck; may reset update download progress.",
        "Stop 'wuauserv' service before clearing, or use Windows Disk Cleanup / Storage Sense.",
    ),
    "deliveryoptimization": (
        "Delivery Optimization Cache",
        "Windows Delivery Optimization",
        "Peer-to-peer and cloud cached update chunks for Windows Updates and Microsoft Store apps.",
        "Low — temporary cache to speed up downloads across local network.",
        "Yes, recreated automatically on future downloads.",
        "None. Saves storage; future updates will be downloaded directly from Microsoft.",
        "Safe to reclaim via Settings > System > Storage > Temporary files > Delivery Optimization.",
    ),
    "system volume information": (
        "System Volume Information",
        "Windows Volume Shadow Copy & Restore",
        "Contains System Restore points, Volume Shadow Copies (VSS), Chkdsk logs, and search indexing DBs.",
        "High — holds recovery checkpoints and backup shadow copies.",
        "System restore points are recreated on schedule or before system changes.",
        "Loss of past restore points and previous file versions for this volume.",
        "Manage allocated space via System Properties > System Protection > Configure.",
    ),
    "recovery": (
        "Windows Recovery Environment (WinRE)",
        "Windows Recovery Subsystem",
        "Contains bootable recovery tools (Winre.wim) used for troubleshooting, reset, and safe mode.",
        "Critical — required for automatic startup repair and PC reset.",
        "Recreated only via DISM or Windows installation media.",
        "Prevents Windows Recovery Environment from launching during boot failure.",
        "Do not delete. Managed automatically by Windows setup.",
    ),
    "$recycle.bin": (
        "Windows Recycle Bin Container",
        "Windows Shell File Reclamation",
        "Per-user staging container for deleted files that can be restored.",
        "User Discretion — contains files previously deleted by users.",
        "Recreated automatically when files are sent to Recycle Bin.",
        "Permanently purges deleted files without possibility of shell restoration.",
        "Safe to empty using desktop Recycle Bin or Windows Storage Sense.",
    ),

    # Application State & Program Folders
    "program files": (
        "64-bit Application Installation Directory",
        "Installed Applications & Software Vendors",
        "Installed binaries, shared libraries, default configurations, and assets for 64-bit software.",
        "High — applications installed here depend on these files to launch and run.",
        "Recreated only by reinstalling the owning applications.",
        "Breaks installed programs, desktop shortcuts, and scheduled background tasks.",
        "Uninstall unwanted programs properly via Windows Settings > Installed apps.",
    ),
    "program files (x86)": (
        "32-bit Application Installation Directory",
        "Installed 32-bit Software",
        "Installed binaries and dependencies for 32-bit software on 64-bit Windows.",
        "High — installed software requires these files to operate.",
        "Recreated only by reinstalling the owning applications.",
        "Breaks 32-bit applications and associated background utilities.",
        "Uninstall via Windows Settings > Installed apps or application uninstaller.",
    ),
    "programdata": (
        "Shared Application Data & Machine Settings",
        "Installed Applications (All Users)",
        "Machine-wide application configurations, shared databases, license caches, and local service data.",
        "High — shared across all user accounts on this machine.",
        "Some caches regenerate, but configuration files and local databases may be lost.",
        "May reset application licensing, wipe local databases, or prevent services from starting.",
        "Do not delete wholesale. Inspect specific application subfolders; use vendor uninstallers.",
    ),
    "appdata": (
        "User Application Data Container",
        "User Profiles & Installed Applications",
        "Root directory for user-specific settings, caches, profiles, and portable installations.",
        "High — contains both disposable caches and irreplaceable application state/databases.",
        "Mixed — caches regenerate, but configuration and local saves do not.",
        "Deleting AppData resets all installed user programs, browser profiles, and local configs.",
        "Do not delete AppData as a whole. Inspect Local/Temp or application cache subfolders.",
    ),
    "roaming": (
        "Roaming User Profile Settings",
        "Windows Roaming Profile Subsystem & Applications",
        "User settings, preferences, and state intended to roam across domain-joined machines.",
        "High — stores application preferences, bookmarks, saved sessions, and configurations.",
        "Rarely recreatable without manual reconfiguration.",
        "Resets application preferences, deletes local state, and may cause data loss.",
        "Never delete entire Roaming directory. Prefer in-app settings reset.",
    ),
    "local": (
        "Local Application Data & Caches",
        "Windows User Profile & Local Applications",
        "Local machine caches, downloaded assets, temporary working data, and per-user app installs.",
        "Medium — contains high-volume caches alongside local application installs (like Chrome/Teams).",
        "Varies: browser and build caches regenerate; per-user app installs will be broken.",
        "Deleting specific cache subdirectories is safe; deleting the whole directory breaks apps.",
        "Target specific subfolders like Temp, or use built-in application cache cleanup.",
    ),
    "locallow": (
        "Low-Integrity Application Data",
        "Sandboxed & Protected Applications",
        "Data written by applications running in low-integrity mode (e.g. sandboxed browsers, plugins).",
        "Medium — stores sandboxed browser data, Unity web player caches, and low-privilege settings.",
        "Caches regenerate automatically.",
        "May reset sandboxed application state or require re-caching of assets.",
        "Safe to review individual subfolders.",
    ),
    "temp": (
        "Temporary Working Directory",
        "Windows OS & Active Applications",
        "Short-term working files, crash logs, in-flight installers, and session caches.",
        "Low — designed for ephemeral data.",
        "Yes, ephemeral data generated on demand.",
        "Files actively locked by open programs cannot and should not be deleted. Old files are safe.",
        "Safe to clean files older than 24-48 hours via DiskLens review or Windows Storage Sense.",
    ),
    "tmp": (
        "Temporary Working Directory",
        "Operating System & Developer Tools",
        "Ephemeral working files, build intermediates, and short-lived session files.",
        "Low — temporary storage.",
        "Yes, automatically regenerated.",
        "Deleting actively in-use files may disrupt running scripts or installations.",
        "Safe to clean when no dependent processes or builds are active.",
    ),
    "downloads": (
        "User Downloads Directory",
        "User Filesystem",
        "Files downloaded from browsers, email clients, and file transfer tools.",
        "User Dependent — files may be one-off installers or irreplaceable documents/archives.",
        "Depends entirely on whether the original web sources are still accessible.",
        "May permanently delete files you intended to save.",
        "User review required. Sort by size/date and move keepers to Documents.",
    ),
    "users": (
        "User Profiles Container",
        "Windows Security & User Subsystem",
        "Contains all local user profile directories, desktop files, documents, and profile registries.",
        "Critical — contains all personal files and user account data.",
        "Cannot be recreated without complete data loss.",
        "Destroys user accounts, documents, desktop files, and application state.",
        "Never delete the Users directory. Manage individual accounts via Windows Settings.",
    ),

    # Web Browsers
    "chrome": (
        "Google Chrome Browser Data & Cache",
        "Google Chrome",
        "Stores browser profile, bookmarks, cached web content, extensions, and local history.",
        "Medium — profile and history are important; Cache/Code Cache is disposable.",
        "Caches recreate automatically on browsing; profile data requires Google Sync to restore.",
        "Deleting 'Cache' frees disk safely; deleting 'User Data' logs you out and resets browser.",
        "Clear cache via Chrome Settings > Clear browsing data, or clean only the Cache/ folder.",
    ),
    "edge": (
        "Microsoft Edge Browser Data & Cache",
        "Microsoft Edge",
        "Stores Edge user profiles, extension state, cached resources, and browser history.",
        "Medium — caches are disposable; user favorites, passwords, and sessions are persistent.",
        "Caches recreate automatically; user profile syncs via Microsoft Account if enabled.",
        "Deleting cache subfolders frees space safely; deleting profile resets Edge settings.",
        "Use Edge Settings > Privacy > Clear browsing data.",
    ),

    # Gaming & Entertainment
    "steam": (
        "Steam Client & Game Content",
        "Valve Steam",
        "Game installations, download staging, workshop items, shaders, and client resources.",
        "High — holds large downloaded game data and client installations.",
        "Games can be re-downloaded from Steam library, but this consumes high bandwidth.",
        "Uninstalls games or removes downloaded assets.",
        "Use Steam Client > Storage Manager to properly move or uninstall games.",
    ),
    "steamapps": (
        "Steam Game Installations & Depots",
        "Valve Steam",
        "Contains installed game folders (common/), manifest files (appmanifest), and shader caches.",
        "High — contains bulk game assets (often hundreds of gigabytes).",
        "Yes, by re-downloading from Steam.",
        "Removes installed games and local modifications.",
        "Uninstall games from within the Steam client; delete leftover shadercache/ if games removed.",
    ),

    # Developer Tools & Environments
    "node_modules": (
        "Node.js Package Dependencies",
        "Node.js / npm / yarn / pnpm",
        "Local dependency packages installed for a JavaScript/TypeScript project.",
        "Medium — required for project builds and execution, but completely regenerable.",
        "Yes, running 'npm install', 'yarn', or 'pnpm install' recreates it from lockfile.",
        "Project will fail to run or build until packages are reinstalled.",
        "Safe to delete for inactive/archived projects to reclaim large amounts of storage.",
    ),
    "_cacache": (
        "npm / Pacote Global Package Cache",
        "npm Package Manager",
        "Cached tarballs and content-addressable blobs of downloaded npm packages.",
        "Low — local cache to accelerate future npm installs.",
        "Yes, packages are downloaded from npm registry when needed.",
        "Future npm installs will fetch from internet rather than local cache.",
        "Safe to clean using 'npm cache clean --force'.",
    ),
    "npm-cache": (
        "npm Global Cache Directory",
        "Node Package Manager",
        "Cached npm packages and index metadata.",
        "Low — temporary download cache.",
        "Yes, recreated automatically during npm operations.",
        "None. Saves storage; subsequent installs re-download needed packages.",
        "Run 'npm cache clean --force'.",
    ),
    ".venv": (
        "Python Virtual Environment",
        "Python venv / virtualenv",
        "Isolated Python interpreter, standard library links, and installed pip packages.",
        "Medium — required to run project scripts, but regenerable from requirements.txt/pyproject.",
        "Yes, recreated with 'python -m venv .venv && pip install -r requirements.txt'.",
        "Project cannot run until virtual environment is re-created.",
        "Safe to remove on archived projects if requirements file or lockfile is preserved.",
    ),
    "venv": (
        "Python Virtual Environment",
        "Python venv / virtualenv",
        "Project-specific Python interpreter binaries and site-packages.",
        "Medium — required for project execution, regenerable from specification.",
        "Yes, re-created via virtualenv or venv module.",
        "Disables project environment until recreated.",
        "Delete only if project is inactive and dependencies are recorded.",
    ),
    "pip": (
        "Python Package Installer Cache",
        "pip / PyPA",
        "Cached wheel files (.whl) and HTTP response cache for downloaded Python packages.",
        "Low — caching layer to speed up repeated package installations.",
        "Yes, packages will be downloaded from PyPI on demand.",
        "Slightly slower package installation on next pip install; frees significant disk space.",
        "Safe to reclaim using 'pip cache purge'.",
    ),
    "__pycache__": (
        "Python Bytecode Cache",
        "Python Interpreter",
        "Compiled Python bytecode files (.pyc) to speed up module loading.",
        "Low — automatically compiled optimization cache.",
        "Yes, Python automatically recompiles .py files on next execution.",
        "Slightly slower first execution while bytecode recompiles.",
        "Safe to delete at any time.",
    ),
    "docker": (
        "Docker Engine Containers & Storage",
        "Docker Desktop / Docker Engine",
        "Container images, overlay2 layers, container writable layers, and persistent volumes.",
        "High — may contain active containers, database volumes, and container state.",
        "Images can be pulled again; persistent volume data cannot be recreated without backups.",
        "May delete production or development database volumes and container state.",
        "Inspect with 'docker system df'; reclaim safely via 'docker system prune'.",
    ),
    ".gradle": (
        "Gradle Build System Cache & Daemons",
        "Gradle Build Tool",
        "Downloaded dependencies, jar artifacts, build cache, and Gradle wrapper distributions.",
        "Medium — speeds up Gradle builds by caching dependencies and execution tasks.",
        "Yes, Gradle re-downloads dependencies from remote repositories (Maven Central).",
        "Next build will take longer as it re-downloads dependencies.",
        "Safe to clean using 'gradle --stop' followed by removing the wrapper/cache directories.",
    ),
    ".m2": (
        "Maven Local Repository & Cache",
        "Apache Maven / Java Ecosystem",
        "Local repository storing downloaded Maven plugins, dependency jars, and locally built artifacts.",
        "Medium — contains third-party jars plus locally built project snapshots.",
        "Remote artifacts are re-downloaded; locally installed custom builds without source will be lost.",
        "Next Maven build re-downloads all dependencies; locally deployed snapshots must be rebuilt.",
        "Safe to clean cached third-party libraries; verify no un-publishable artifacts exist.",
    ),
    ".vscode": (
        "Visual Studio Code Workspace Settings",
        "Microsoft Visual Studio Code",
        "Workspace-specific editor settings, task definitions, launch configurations, and recommendations.",
        "Low to Medium — contains developer configuration for the specific project.",
        "Partially, default configs can be recreated manually.",
        "Loses project-specific debug launch profiles and custom editor tasks.",
        "Review before deleting; preserve launch.json and tasks.json if customized.",
    ),
    "code": (
        "Visual Studio Code Application State & Cache",
        "Visual Studio Code",
        "Installed extensions, editor cache, language server caches, and UI state.",
        "Medium — caches are disposable; installed extensions and user settings should be preserved.",
        "Caches regenerate; extensions re-install from Marketplace.",
        "Clearing cache speeds up editor; clearing user data resets extensions and preferences.",
        "Safe to clear Code/Cache and Code/CachedData directories.",
    ),
    ".git": (
        "Git Version Control Repository Data",
        "Git VCS",
        "Full commit history, branches, refs, stashes, and remote tracking for a repository.",
        "Critical for projects — contains the entire version history and unpushed branches.",
        "Cannot be recreated if local branches or stashes have not been pushed to remote.",
        "Permanently destroys repository history, unpushed commits, stashes, and version tracking.",
        "Never delete .git unless you explicitly want to decouple the folder from version control.",
    ),
    "wsl": (
        "Windows Subsystem for Linux Distributions",
        "Microsoft WSL",
        "Linux distribution root filesystems, VHDX virtual hard disks, and user environment.",
        "High — contains full Linux operating system, home directories, and installed Linux packages.",
        "Linux distribution can be reinstalled, but user data inside will be permanently lost.",
        "Destroys Linux files, databases, and development environments.",
        "Manage storage using 'wsl --compact' or unregister unused distributions with 'wsl --unregister'.",
    ),
    "wsl$": (
        "WSL Network Share Mount",
        "Windows Subsystem for Linux",
        "Network redirector providing Windows access to active WSL Linux filesystems.",
        "Virtual — representation of live Linux files.",
        "Virtual mount point.",
        "Access to Linux filesystem from Windows.",
        "Do not delete files through wsl$ unless intending to delete them from inside Linux.",
    ),
    "onedrive": (
        "Microsoft OneDrive Cloud Sync Folder",
        "Microsoft OneDrive",
        "Locally cached and synchronized copies of cloud-stored personal and work documents.",
        "High — synchronized personal/business files.",
        "Files marked 'cloud only' exist remotely; locally modified un-synced files may be lost.",
        "Deleting files in OneDrive deletes them from the cloud and all other synchronized devices.",
        "Use OneDrive 'Free up space' right-click option to make files online-only without deletion.",
    ),
}


def parts(path) -> tuple[str, ...]:
    """Return lowercase path components."""
    return tuple(p.casefold() for p in PureWindowsPath(str(path).replace("/", "\\")).parts)


def explain(path) -> dict[str, Any]:
    """Explain what a file or directory is, who uses it, why it exists, and its deletion risks."""
    path_parts = parts(path)

    # Check from deepest component to root for the most specific match
    for part in reversed(path_parts):
        if part in KB_ENTRIES:
            (
                title,
                owner,
                purpose,
                importance,
                recreatable,
                consequences,
                recommendation,
            ) = KB_ENTRIES[part]
            return {
                "source": "curated knowledge base",
                "context": part,
                "title": title,
                "owner": owner,
                "purpose": purpose,
                "importance": importance,
                "recreatable": recreatable,
                "consequences": consequences,
                "recommendation": recommendation,
            }

    # If no directory match, provide intelligent explanation based on file extension
    ext = Path(path).suffix.lower()
    from .visualization import CATEGORY_EXTENSIONS

    for category, exts in CATEGORY_EXTENSIONS.items():
        if ext in exts:
            return {
                "source": "extension analysis",
                "context": ext,
                "title": f"{category} File ({ext})",
                "owner": "Application or User",
                "purpose": f"Standard {category.lower()} resource.",
                "importance": "User / application dependent.",
                "recreatable": "Depends on original source or generating application.",
                "consequences": "Application or document loss if removed without backup.",
                "recommendation": "Review file contents and owning application before deletion.",
            }

    return {
        "source": "unknown",
        "context": str(Path(path).name),
        "title": "Unrecognized Location",
        "owner": "Unknown",
        "purpose": "Not established from available system and directory evidence.",
        "importance": "Unknown — dependencies not verified.",
        "recreatable": "Unknown.",
        "consequences": "Dependencies and deletion consequences are unknown. Retain pending review.",
        "recommendation": "Do not delete unknown files without verifying owning application or backups.",
    }


def location(path) -> str:
    """Classify the broad location context for deterministic safety assessment and ML features."""
    p = set(parts(path))
    if p & {
        "windows",
        "system32",
        "syswow64",
        "winsxs",
        "boot",
        "efi",
        "system volume information",
        "recovery",
    }:
        return "system"
    if p & {"program files", "program files (x86)", "programdata", "roaming"}:
        return "application"
    if p & {"temp", "tmp"}:
        return "temp"
    if p & {"cache", "caches", ".cache", "_cacache", "shadercache", "softwaredistribution"}:
        return "cache"
    if p & {
        "node_modules",
        ".venv",
        "venv",
        ".gradle",
        ".m2",
        "sdk",
        "docker",
        ".git",
        ".vscode",
        "site-packages",
        "__pycache__",
        "pip",
    }:
        return "development"
    if p & {"documents", "downloads", "pictures", "videos", "desktop", "music", "onedrive", "backups"}:
        return "personal"
    return "unknown"


def category_rule(record: dict) -> str:
    """Fast deterministic rule mapping metadata record to file purpose category."""
    loc = location(record["path"])
    ext = record.get("extension", "").lower()
    if loc == "system":
        return "operating_system"
    if ext in {".doc", ".docx", ".pdf", ".txt", ".odt", ".xlsx", ".pptx", ".csv", ".rtf", ".md"}:
        return "document"
    if ext in {".mp4", ".mp3", ".png", ".jpg", ".jpeg", ".wav", ".mkv", ".flac", ".gif", ".webp"}:
        return "media"
    if ext in {".zip", ".7z", ".tar", ".gz", ".bak", ".rar", ".bz2", ".xz"}:
        return "archive"
    if ext in {".msi", ".msix", ".appx"}:
        return "installer"
    if ext in {".db", ".sqlite", ".ini", ".yaml", ".toml", ".json", ".dll", ".exe", ".sys", ".cfg"}:
        return "application"
    if ext == ".log":
        return "log"
    return {
        "temp": "temporary",
        "cache": "cache",
        "development": "development",
        "application": "application",
        "personal": "document",
    }.get(loc, "unknown")
