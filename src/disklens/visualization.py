"""Clean terminal storage visualizations: usage bars, directory size trees, and category rollups."""

import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from rich.table import Table
from rich.tree import Tree

CATEGORY_EXTENSIONS = {
    "Documents": {
        ".doc",
        ".docx",
        ".pdf",
        ".txt",
        ".odt",
        ".xlsx",
        ".xls",
        ".pptx",
        ".ppt",
        ".csv",
        ".rtf",
        ".md",
        ".epub",
        ".pages",
        ".numbers",
        ".key",
    },
    "Images": {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".svg",
        ".ico",
        ".tiff",
        ".tif",
        ".raw",
        ".heic",
    },
    "Videos": {
        ".mp4",
        ".mkv",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".webm",
        ".m4v",
        ".mpg",
        ".mpeg",
        ".3gp",
    },
    "Audio": {
        ".mp3",
        ".wav",
        ".flac",
        ".aac",
        ".ogg",
        ".wma",
        ".m4a",
        ".opus",
        ".aiff",
        ".mid",
    },
    "Applications": {
        ".exe",
        ".dll",
        ".msi",
        ".msix",
        ".sys",
        ".appx",
        ".bat",
        ".cmd",
        ".ps1",
        ".com",
        ".scr",
    },
    "Archives": {
        ".zip",
        ".7z",
        ".tar",
        ".gz",
        ".rar",
        ".bz2",
        ".xz",
        ".tgz",
        ".iso",
        ".cab",
        ".dmg",
    },
    "Development": {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".go",
        ".rs",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".scss",
        ".sql",
        ".sh",
        ".php",
        ".rb",
        ".swift",
        ".kt",
    },
    "Temporary": {
        ".tmp",
        ".temp",
        ".cache",
        ".log",
        ".bak",
        ".old",
        ".swp",
        ".dmp",
        ".chk",
        ".part",
        ".crdownload",
    },
}


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-readable compact string (e.g. '14.2 GB', '512 KB')."""
    if num_bytes is None or math.isnan(num_bytes) or num_bytes < 0:
        return "0 B"
    num = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num) < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(num)} B"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def render_bar(
    used: int,
    total: int,
    width: int = 18,
    fill_char: str = "█",
    empty_char: str = "░",
) -> str:
    """Render a text storage bar, e.g. [████████████░░░░░░] 66.7%."""
    if total <= 0:
        return f"[{empty_char * width}] 0.0%"
    fraction = min(1.0, max(0.0, used / total))
    filled_len = round(fraction * width)
    empty_len = width - filled_len
    percent_str = f"{fraction * 100:.1f}%"
    return f"[{fill_char * filled_len}{empty_char * empty_len}] {percent_str}"


def classify_category(extension: str, path_str: str) -> str:
    """Classify a file into one of the main user-facing storage categories."""
    ext = (extension or "").lower()
    path_lower = path_str.replace("\\", "/").lower()
    parts = set(path_lower.split("/"))

    # Check system location first
    if parts & {"windows", "system32", "syswow64", "winsxs", "boot", "efi"}:
        return "System"

    # Check development directory context
    if parts & {"node_modules", ".venv", "venv", ".git", ".gradle", ".m2", "__pycache__"}:
        return "Development"

    # Check temp / cache directories
    if parts & {"temp", "tmp", "cache", "caches", "_cacache"}:
        return "Temporary"

    # Match by extension
    for category, extensions in CATEGORY_EXTENSIONS.items():
        if ext in extensions:
            return category

    return "Other"


def get_category_summary(db, scan_id: str) -> list[dict[str, Any]]:
    """Aggregate files by high-level storage category for a saved scan."""
    # Query extension, path, size from files table
    categories: dict[str, dict[str, Any]] = defaultdict(lambda: {"files": 0, "bytes": 0})
    total_bytes = 0

    rows = db.conn.execute(
        "SELECT extension, path, size FROM files WHERE scan_id=? AND is_directory=0",
        (scan_id,),
    ).fetchall()

    for ext, path_str, size in rows:
        cat = classify_category(ext, path_str)
        categories[cat]["files"] += 1
        categories[cat]["bytes"] += size or 0
        total_bytes += size or 0

    result = []
    for name, data in categories.items():
        pct = (data["bytes"] / total_bytes * 100.0) if total_bytes > 0 else 0.0
        result.append(
            {
                "category": name,
                "files": data["files"],
                "bytes": data["bytes"],
                "percent": round(pct, 1),
            }
        )

    result.sort(key=lambda r: -r["bytes"])
    return result


def render_drives_table(drives: list[Any]) -> Table:
    """Build a Rich Table showing all discovered drives with usage bars."""
    table = Table(title="Available Drives & Volumes", show_lines=False)
    table.add_column("Drive", style="cyan bold", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Label / FS", style="green")
    table.add_column("Total", justify="right")
    table.add_column("Used", justify="right")
    table.add_column("Free", justify="right")
    table.add_column("Utilization", style="yellow")
    table.add_column("Status", style="blue")

    for d in drives:
        if d.is_ready:
            bar = render_bar(d.used_bytes, d.total_bytes, width=16)
            label_fs = f"{d.label} ({d.filesystem})" if d.label else d.filesystem or "Ready"
            status = "Scannable" if d.is_suitable_for_scan else "Ready"
            table.add_row(
                d.path,
                d.drive_type,
                label_fs,
                format_bytes(d.total_bytes),
                format_bytes(d.used_bytes),
                format_bytes(d.free_bytes),
                bar,
                status,
            )
        else:
            table.add_row(
                d.path,
                d.drive_type,
                "-",
                "-",
                "-",
                "-",
                "[░░░░░░░░░░░░░░░░] N/A",
                d.error or "Unavailable",
                style="dim",
            )

    return table


def render_category_table(categories: list[dict[str, Any]], total_bytes: int) -> Table:
    """Build a Rich Table showing storage by category with visual bars."""
    table = Table(title="Storage Distribution by Category", show_lines=False)
    table.add_column("Category", style="cyan bold")
    table.add_column("Files", justify="right", style="magenta")
    table.add_column("Storage", justify="right", style="green bold")
    table.add_column("Share", style="yellow")

    for cat in categories:
        bar = render_bar(cat["bytes"], total_bytes, width=16)
        table.add_row(
            cat["category"],
            f"{cat['files']:,}",
            format_bytes(cat["bytes"]),
            bar,
        )

    return table


def build_size_tree(
    db,
    scan_id: str,
    root_path: str,
    max_depth: int = 2,
    max_children: int = 6,
) -> Tree:
    """Build a Rich Tree showing hierarchical directory sizes."""
    # Build direct child aggregates from DB
    root = Path(root_path).absolute()
    child_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"bytes": 0, "files": 0})

    # Query all files and sum directly to immediate subfolders up to max_depth
    rows = db.conn.execute(
        "SELECT path, size FROM files WHERE scan_id=? AND is_directory=0",
        (scan_id,),
    ).fetchall()

    for path_str, size in rows:
        p = Path(path_str)
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        parts = rel.parts
        # Accumulate for each depth prefix
        for depth in range(1, min(len(parts), max_depth + 2)):
            prefix_path = str(root.joinpath(*parts[:depth]))
            child_totals[prefix_path]["bytes"] += size or 0
            child_totals[prefix_path]["files"] += 1

    root_bytes = child_totals.get(str(root), {}).get("bytes", 0)
    if root_bytes == 0:
        root_bytes = sum(
            data["bytes"]
            for path_k, data in child_totals.items()
            if Path(path_k).parent == root
        )

    tree = Tree(
        f"[bold cyan]{root}[/] [green bold]({format_bytes(root_bytes)})[/]"
    )

    def add_children(parent_node: Tree, parent_path: Path, current_depth: int):
        if current_depth > max_depth:
            return
        # Find all direct children of parent_path
        children = []
        for path_k, data in child_totals.items():
            child_p = Path(path_k)
            if child_p.parent == parent_path and child_p != parent_path:
                children.append((child_p, data["bytes"], data["files"]))

        # Sort by bytes descending
        children.sort(key=lambda item: -item[1])

        for child_p, c_bytes, c_files in children[:max_children]:
            # Percent of parent
            parent_bytes = child_totals.get(str(parent_path), {}).get("bytes", root_bytes)
            pct = (c_bytes / parent_bytes * 100.0) if parent_bytes > 0 else 0.0
            label = (
                f"[bold]{child_p.name}[/] "
                f"[green]{format_bytes(c_bytes)}[/] "
                f"[dim]({pct:.1f}%)[/]"
            )
            node = parent_node.add(label)
            add_children(node, child_p, current_depth + 1)

        if len(children) > max_children:
            remaining = sum(c[1] for c in children[max_children:])
            parent_node.add(f"[dim]... {len(children) - max_children} more ({format_bytes(remaining)})[/dim]")

    add_children(tree, root, 1)
    return tree


def render_html_report(data: dict[str, Any]) -> str:
    """Generate a clean, styled, self-contained HTML report."""
    import html as html_lib
    import json

    title = "DiskLens Storage Report"
    scan = data.get("scan", {})
    root = scan.get("root", "N/A")
    file_count = scan.get("file_count", 0)
    unique_bytes = scan.get("unique_bytes", 0)
    status = scan.get("status", "complete")
    elapsed = scan.get("elapsed", 0.0)

    # Categories if present
    categories = data.get("categories", [])
    largest_files = data.get("largest_files", [])

    rows_cat = ""
    for cat in categories:
        bar_pct = cat.get("percent", 0.0)
        rows_cat += f"""
        <tr>
            <td><strong>{html_lib.escape(str(cat.get('category', '')))}</strong></td>
            <td style="text-align: right;">{cat.get('files', 0):,}</td>
            <td style="text-align: right;">{format_bytes(cat.get('bytes', 0))}</td>
            <td>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {min(100.0, bar_pct)}%;"></div>
                </div>
                <small>{bar_pct:.1f}%</small>
            </td>
        </tr>
        """

    rows_files = ""
    for f in largest_files[:20]:
        rows_files += f"""
        <tr>
            <td class="code-path">{html_lib.escape(str(f.get('path', '')))}</td>
            <td style="text-align: right;"><strong>{format_bytes(f.get('size', 0))}</strong></td>
            <td>{html_lib.escape(str(f.get('extension', '')))}</td>
        </tr>
        """

    raw_json = html_lib.escape(json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — {html_lib.escape(str(root))}</title>
<style>
  :root {{
    --bg: #f8fafc;
    --card: #ffffff;
    --text: #0f172a;
    --text-muted: #64748b;
    --border: #e2e8f0;
    --primary: #2563eb;
    --primary-light: #dbeafe;
    --success: #16a34a;
    --warning: #ea580c;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f172a;
      --card: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --primary: #3b82f6;
      --primary-light: #1e3a8a;
    }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  header {{ margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }}
  h1 {{ margin: 0 0 8px 0; font-size: 24px; color: var(--primary); }}
  .meta {{ color: var(--text-muted); font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  .card-label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; }}
  .card-value {{ font-size: 22px; font-weight: bold; color: var(--text); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--bg); font-weight: 600; color: var(--text-muted); }}
  .progress-bar {{ background: var(--border); border-radius: 4px; height: 8px; width: 120px; display: inline-block; vertical-align: middle; margin-right: 8px; overflow: hidden; }}
  .progress-fill {{ background: var(--primary); height: 100%; }}
  .code-path {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; word-break: break-all; }}
  details {{ margin-top: 24px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }}
  summary {{ cursor: pointer; font-weight: 600; color: var(--primary); }}
  pre {{ overflow-x: auto; font-size: 12px; background: var(--bg); padding: 12px; border-radius: 6px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>DiskLens — Storage Intelligence Report</h1>
    <div class="meta">Target Scope: <strong>{html_lib.escape(str(root))}</strong> &bull; Scan Status: <span style="text-transform: capitalize;">{status}</span></div>
  </header>

  <div class="grid">
    <div class="card">
      <div class="card-label">Total Storage Scanned</div>
      <div class="card-value">{format_bytes(unique_bytes)}</div>
    </div>
    <div class="card">
      <div class="card-label">Total Files</div>
      <div class="card-value">{file_count:,}</div>
    </div>
    <div class="card">
      <div class="card-label">Scan Time</div>
      <div class="card-value">{elapsed:.2f}s</div>
    </div>
    <div class="card">
      <div class="card-label">Scan Status</div>
      <div class="card-value">{status.upper()}</div>
    </div>
  </div>

  {'<div class="card" style="margin-bottom: 24px;"><h3>Storage Categories</h3><table><thead><tr><th>Category</th><th style="text-align: right;">Files</th><th style="text-align: right;">Size</th><th>Share</th></tr></thead><tbody>' + rows_cat + '</tbody></table></div>' if rows_cat else ''}

  {'<div class="card" style="margin-bottom: 24px;"><h3>Top Largest Files</h3><table><thead><tr><th>Path</th><th style="text-align: right;">Size</th><th>Type</th></tr></thead><tbody>' + rows_files + '</tbody></table></div>' if rows_files else ''}

  <details>
    <summary>View Complete Raw Data (JSON)</summary>
    <pre>{raw_json}</pre>
  </details>
</div>
</body>
</html>"""
