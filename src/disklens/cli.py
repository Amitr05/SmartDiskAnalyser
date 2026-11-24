"""CLI-first DiskLens. All filesystem analysis is non-destructive and read-only."""

import csv
import functools
import html
import io
import json
import os
import sqlite3
import sys
import time
import tomllib
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import analysis
from .apps import analyze_application_storage
from .database import Database
from .drives import get_available_drives, get_scannable_drives
from .duplicates import digest, find_duplicates
from .knowledge import category_rule, explain
from .ml.data import demo_dataset, load_jsonl, reconcile
from .ml.training import load_model, predict, train
from .query import answer
from .safety import assess
from .scanner import metadata
from .visualization import (
    build_size_tree,
    format_bytes,
    get_category_summary,
    render_bar,
    render_category_table,
    render_drives_table,
    render_html_report,
)

app = typer.Typer(
    help="DiskLens: Intelligent, risk-aware Windows filesystem explorer and disk analyzer.",
    no_args_is_help=False,
)
console = Console(stderr=True)


def guarded(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, OSError, sqlite3.Error, KeyError, json.JSONDecodeError) as exc:
            console.print(f"Error: {exc}", style="red", markup=False)
            raise typer.Exit(1) from exc

    return wrapped


def normalize(path):
    value = str(path)
    if os.name == "nt" and len(value) == 2 and value[1] == ":":
        value += "\\"
    return Path(value).absolute()


def resolve_user_path(path_input: str | Path | None) -> Path:
    if path_input is None:
        return Path.home()
    raw = str(path_input).strip()
    if not raw:
        return Path.home()
    p = Path(raw)
    if p.exists():
        return p.resolve()
    trimmed = raw.lstrip("\\/")
    cand_home = Path.home() / trimmed
    if cand_home.exists():
        return cand_home.resolve()
    cand_cwd = Path.cwd() / trimmed
    if cand_cwd.exists():
        return cand_cwd.resolve()
    return normalize(p)


@contextmanager
def database(ctx):
    db = Database(ctx.obj["db"])
    try:
        yield db
    finally:
        db.close()


def emit(ctx, value):
    fmt = ctx.obj["format"]
    if fmt == "csv":
        rows = value if isinstance(value, list) else [value]
        rows = [r if isinstance(r, dict) else {"value": r} for r in rows]
        buffer = io.StringIO()
        keys = list(dict.fromkeys(key for row in rows for key in row))
        writer = csv.DictWriter(buffer, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            # Prevent spreadsheet formula execution from adversarial filenames.
            clean = {}
            for k, v in row.items():
                cell = json.dumps(v) if isinstance(v, (list, dict)) else v
                if isinstance(cell, str) and cell.startswith(("=", "+", "-", "@", "\t", "\r")):
                    cell = "'" + cell
                clean[k] = cell
            writer.writerow(clean)
        text = buffer.getvalue()
    elif fmt == "html":
        if isinstance(value, dict):
            text = render_html_report(value)
        else:
            json_text = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False)
            text = (
                '<!doctype html><meta charset="utf-8"><title>DiskLens report</title><h1>DiskLens</h1><pre>'
                + html.escape(json_text)
                + "</pre>"
            )
    else:
        text = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False)

    output = ctx.obj["output"]
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="") as handle:
            handle.write(text + "\n")
        console.print(f"Created {output}", markup=False)
    elif fmt == "terminal":
        Console().print(text, markup=False, highlight=False)
    else:
        typer.echo(text)


def model_for(ctx):
    path = ctx.obj.get("model")
    if path is None:
        return None
    return load_model(path)


def inspect_path(ctx, path):
    path = normalize(path)
    rec = metadata(path, path.parent).to_dict()
    result = {
        "facts": rec,
        "knowledge": explain(path),
        "rule_category_hint": category_rule(rec),
        "safety": assess(rec, live=True).to_dict(),
    }
    model = model_for(ctx)
    if model:
        result["ml"] = predict(model, rec, ctx.obj["allow_demo"])
    else:
        result["ml"] = {
            "status": "not_loaded",
            "decision": "unknown",
            "category": "unknown",
            "reason": "No trained model loaded. Pass --model <path> to enable ML predictions.",
        }
    return result


@app.callback(invoke_without_command=True)
@guarded
def main(
    ctx: typer.Context,
    db: Annotated[
        Path | None, typer.Option(help="SQLite state path; default ~/.disklens/history.sqlite")
    ] = None,
    model: Annotated[
        Path | None, typer.Option(help="TRUSTED local model.joblib only; joblib can execute code.")
    ] = None,
    format: Annotated[
        str, typer.Option("--format", help="terminal, json, csv, html; put global options before command")
    ] = "terminal",
    output: Annotated[
        Path | None, typer.Option(help="New output file; existing files are never overwritten.")
    ] = None,
    config: Annotated[Path | None, typer.Option(help="TOML config with [disklens] table")] = None,
    verbose: bool = False,
    allow_demo: Annotated[
        bool, typer.Option(help="Show synthetic model predictions; recommendations remain blocked.")
    ] = False,
):
    settings = {}
    if config:
        with config.open("rb") as handle:
            settings = tomllib.load(handle).get("disklens", {})
    if format not in {"terminal", "json", "csv", "html"}:
        raise ValueError("Unknown output format")
    ctx.obj = {
        "db": db or Path(settings.get("db", Path.home() / ".disklens/history.sqlite")),
        "model": model or (Path(settings["model"]) if "model" in settings else None),
        "format": format,
        "output": output,
        "verbose": verbose,
        "allow_demo": allow_demo,
        "exclude": settings.get("exclude", []),
    }
    if ctx.invoked_subcommand is None:
        if not sys.stdin.isatty():
            typer.echo(ctx.get_help())
        else:
            interactive(ctx)


@app.command()
@guarded
def drives(ctx: typer.Context):
    """Discover and display all mounted Windows drives, capacity, and usage bars."""
    drive_list = get_available_drives()
    if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
        Console().print(render_drives_table(drive_list))
    else:
        emit(ctx, [d.to_dict() for d in drive_list])


@app.command()
@guarded
def scan(
    ctx: typer.Context,
    path: Annotated[
        Path | None,
        typer.Argument(help="Path or drive to scan. If omitted with --all, scans all available drives."),
    ] = None,
    all: Annotated[
        bool,
        typer.Option("--all", "-a", help="Scan all available suitable drives automatically."),
    ] = False,
    exclude: Annotated[
        list[str] | None, typer.Option(help="Repeat glob patterns, matched to names or relative paths.")
    ] = None,
):
    """Stream directory or drive metadata into SQLite. Use --all to scan entire computer."""
    with database(ctx) as db:
        excludes = list(ctx.obj["exclude"]) + (exclude or [])

        # Handle --all drives scan
        if all:
            scannable = get_scannable_drives()
            if not scannable:
                console.print("[yellow]No accessible drives found to scan.[/yellow]")
                return
            console.print(f"[bold cyan]Scanning all available drives ({len(scannable)} detected)...[/bold cyan]")
            results = []
            for d in scannable:
                console.print(f"\n[bold]Scanning drive {d.path} ({d.label or d.drive_type})...[/bold]")
                progress = (lambda n: console.print(f"  {n:,} files scanned")) if ctx.obj["verbose"] else None
                try:
                    res = db.scan(Path(d.path), excludes, progress)
                    results.append(res)
                    console.print(f"  ✓ Finished {d.path}: {res['file_count']:,} files ({format_bytes(res['unique_bytes'])})")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"  ✗ Error scanning {d.path}: {exc}", style="red")

            summary_report = {
                "scan_type": "all_drives",
                "drives_scanned": len(results),
                "scans": results,
                "total_files": sum(s.get("file_count", 0) for s in results),
                "total_logical_bytes": sum(s.get("logical_bytes", 0) for s in results),
                "total_unique_bytes": sum(s.get("unique_bytes", 0) for s in results),
            }
            if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
                console.rule("[bold green]Computer Scan Complete[/bold green]")
                console.print(
                    f"Drives Scanned: [bold]{len(results)}[/] | "
                    f"Total Files: [bold]{summary_report['total_files']:,}[/] | "
                    f"Total Storage: [bold green]{format_bytes(summary_report['total_unique_bytes'])}[/bold green]"
                )
            else:
                emit(ctx, summary_report)
            return

        if path is None:
            if sys.stdin.isatty():
                console.print(render_drives_table(get_available_drives()))
                choice = typer.prompt("Enter drive letter or path to scan (or 'all' for full scan)", default="all")
                if choice.strip().lower() == "all":
                    scan(ctx, path=None, all=True, exclude=exclude)
                    return
                path = Path(choice.strip())
            else:
                raise ValueError("Specify a path to scan or pass --all to scan all drives.")

        target_path = normalize(path)
        is_terminal = ctx.obj["format"] == "terminal" and not ctx.obj.get("output")
        if is_terminal:
            console.print(f"[bold cyan]Scanning directory:[/] [bold]{target_path}[/]")
            if target_path == target_path.anchor or str(target_path).endswith(":\\"):
                console.print("[dim yellow]Notice: Scanning an entire drive root encompasses hundreds of thousands of files and may take several minutes.[/dim yellow]")
            with console.status(f"[bold cyan]Scanning {target_path.name or target_path}...[/bold cyan]") as status:
                def live_progress(count, bytes_scanned=0, current_path=""):
                    status.update(
                        f"[bold cyan]Scanning {target_path.name or target_path}:[/] "
                        f"[bold green]{count:,}[/] files ([dim]{format_bytes(bytes_scanned)}[/dim])"
                    )

                result = db.scan(target_path, excludes, live_progress)

            rate = int(result["file_count"] / max(result["elapsed"], 0.001))
            status_style = "green" if result["status"] == "complete" else "yellow"
            console.rule(f"[bold {status_style}]Scan {result['status'].capitalize()}[/bold {status_style}]")
            console.print(
                f"Directory: [bold]{result['root']}[/] | "
                f"Files: [bold]{result['file_count']:,}[/] | "
                f"Storage: [bold green]{format_bytes(result['unique_bytes'])}[/] | "
                f"Time: [bold]{result['elapsed']:.1f}s[/] ([dim]{rate:,} files/s[/dim])"
            )
            if result.get("error_count", 0) > 0:
                console.print(f"[dim yellow]({result['error_count']:,} inaccessible system/permission items skipped)[/dim yellow]")
            console.print("[dim]Run 'disklens analyze' or 'disklens tree' to inspect findings.[/dim]\n")
        else:
            progress = (lambda n, *_: console.print(f"{n:,} files scanned")) if ctx.obj["verbose"] else None
            emit(ctx, db.scan(target_path, excludes, progress))


def selected(ctx, db, path=None, scan_id=None):
    if path is not None:
        return db.scan(normalize(path), ctx.obj["exclude"])
    return db.latest(scan_id)


@app.command()
@guarded
def analyze(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Scan a supplied path, or analyze a saved scan (latest by default)."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        summary_data = analysis.summary(db, current)
        cat_summary = get_category_summary(db, current["id"])
        summary_data["categories"] = cat_summary

        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            console.rule(f"[bold cyan]Storage Analysis: {current['root']}[/bold cyan]")
            if current.get("volume_total"):
                vol_bar = render_bar(current.get("volume_used", 0), current.get("volume_total", 1))
                console.print(
                    f"Volume Usage: [bold]{current['root'][:3]}[/] "
                    f"{format_bytes(current.get('volume_used', 0))} used / {format_bytes(current.get('volume_total', 0))} total "
                    f"{vol_bar}"
                )
            console.print(
                f"Scanned Scope: [green]{current['file_count']:,} files[/], "
                f"[bold green]{format_bytes(current['unique_bytes'])} unique[/] "
                f"({format_bytes(current['logical_bytes'])} logical). Status: [bold]{current['status'].upper()}[/]."
            )

            # High-level category breakdown
            if cat_summary:
                Console().print(render_category_table(cat_summary, current["unique_bytes"]))

            # Largest directories
            largest_dirs = summary_data.get("largest_directories", [])[:10]
            if largest_dirs:
                dt = Table(title="Largest Directories", show_lines=False)
                dt.add_column("Directory", style="cyan")
                dt.add_column("Size", justify="right", style="bold green")
                dt.add_column("Files", justify="right", style="dim")
                for d in largest_dirs:
                    dt.add_row(d["path"], format_bytes(d["bytes"]), f"{d['files']:,}")
                Console().print(dt)

            # Largest files
            largest_files = summary_data.get("largest_files", [])[:10]
            if largest_files:
                ft = Table(title="Largest Files", show_lines=False)
                ft.add_column("Path", style="dim")
                ft.add_column("Size", justify="right", style="bold yellow")
                ft.add_column("Risk", style="bold")
                for f in largest_files:
                    ft.add_row(f["path"], format_bytes(f["size"]), assess(f).risk)
                Console().print(ft)
        else:
            emit(ctx, summary_data)


@app.command()
@guarded
def tree(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Argument(help="Root directory for tree visualization")] = None,
    depth: Annotated[int, typer.Option("--depth", "-d", help="Maximum directory depth (default 2)")] = 2,
    scan_id: Annotated[str | None, typer.Option(help="Saved scan ID (defaults to latest)")] = None,
):
    """Display a directory size hierarchy tree with branch sizes."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        rich_tree = build_size_tree(db, current["id"], current["root"], max_depth=depth)
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            Console().print(rich_tree)
        else:
            emit(ctx, {"scan": current, "directories": analysis.directories(db, current)})


@app.command()
@guarded
def categories(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Argument(help="Path to analyze")] = None,
    scan_id: Annotated[str | None, typer.Option(help="Saved scan ID (defaults to latest)")] = None,
):
    """Display storage distribution grouped by high-level category with usage bars."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        cat_summary = get_category_summary(db, current["id"])
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            Console().print(render_category_table(cat_summary, current["unique_bytes"]))
        else:
            emit(ctx, {"scan": current, "categories": cat_summary})


@app.command()
@guarded
def inspect(ctx: typer.Context, path: Path, deep: bool = False):
    """Explain a file or folder: purpose, owning application, importance, and safety."""
    result = inspect_path(ctx, path)
    if deep and not result["facts"]["is_directory"]:
        from .identification import identify

        result["format_inspection"] = identify(normalize(path))

    if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
        know = result.get("knowledge", {})
        safety = result.get("safety", {})
        console.rule(f"[bold cyan]Inspection: {path}[/bold cyan]")
        console.print(f"[bold]Title:[/] {know.get('title', 'Unknown')}")
        console.print(f"[bold]Owning App / Component:[/] [cyan]{know.get('owner', 'Unknown')}[/cyan]")
        console.print(f"[bold]Purpose:[/] {know.get('purpose', 'N/A')}")
        console.print(f"[bold]Importance:[/] {know.get('importance', 'N/A')}")
        console.print(f"[bold]Recreatable:[/] {know.get('recreatable', 'N/A')}")
        console.print(f"[bold]Deletion Consequences:[/] {know.get('consequences', 'N/A')}")
        console.print(f"[bold]Safe Cleanup Recommendation:[/] [green]{know.get('recommendation', 'N/A')}[/green]")
        console.print(f"\n[bold]Safety Risk Tier:[/] [bold red if safety.get('risk')=='CRITICAL' else 'yellow']{safety.get('risk')}[/]")
        console.print(f"[bold]Recommended Action:[/] {safety.get('action')}")
        if result.get("format_inspection"):
            console.print(f"[bold]Format Magic Bytes:[/] {result['format_inspection'].get('signature_hint')}")
    else:
        emit(ctx, result)


@app.command()
@guarded
def risk(ctx: typer.Context, path: Path):
    """Run independent safety rules and the live Windows Resource Protection check."""
    result = inspect_path(ctx, path)
    emit(
        ctx,
        {
            "path": str(normalize(path)),
            "safety": result["safety"],
            "ml": result["ml"],
            "warning": "No deletion authorization. Unknown dependencies remain unknown.",
        },
    )


@app.command()
@guarded
def largest(ctx: typer.Context, path: Path | None = None, limit: int = 20, scan_id: str | None = None):
    """Find largest regular files, without hashing contents."""
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be 1..10000")
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        files = analysis.largest(db, current["id"], limit)
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            t = Table(title=f"Top {len(files)} Largest Files ({current['root']})", show_lines=False)
            t.add_column("#", justify="right", style="dim")
            t.add_column("File Path", style="cyan")
            t.add_column("Size", justify="right", style="bold yellow")
            t.add_column("Risk Tier", style="bold")
            t.add_column("Context", style="dim")
            for i, f in enumerate(files, 1):
                t.add_row(
                    str(i),
                    f["path"],
                    format_bytes(f["size"]),
                    assess(f).risk,
                    explain(f["path"]).get("title", ""),
                )
            Console().print(t)
        else:
            emit(ctx, files)


@app.command()
@guarded
def duplicates(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Find verified duplicate files via SHA-256 and byte comparison. Never delete copies."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        dup_data = find_duplicates(db, current["id"])
        payload = {"scan": current, **dup_data}
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            groups = dup_data.get("groups", [])
            pot_bytes = dup_data.get("potential_bytes", 0)
            console.rule(f"[bold cyan]Duplicate Files Analysis: {current['root']}[/bold cyan]")
            if not groups:
                console.print("[green]No content-verified duplicate groups found.[/green]")
            else:
                console.print(
                    f"Found [bold yellow]{len(groups)}[/] duplicate groups. "
                    f"Potential reclaimable storage: [bold green]{format_bytes(pot_bytes)}[/bold green]."
                )
                for i, g in enumerate(groups[:10], 1):
                    t = Table(
                        title=f"Group #{i} — {format_bytes(g['size_each'])} each (SHA-256: {g['sha256'][:12]}...)",
                        show_lines=False,
                    )
                    t.add_column("Identical File Copies", style="cyan")
                    for p in g["paths"]:
                        t.add_row(p)
                    Console().print(t)
                if len(groups) > 10:
                    console.print(f"[dim]... and {len(groups) - 10} more duplicate groups.[/dim]")
        else:
            emit(ctx, payload)


@app.command()
@guarded
def anomalies(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Fit Isolation Forest on directory metadata to detect structural outliers."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        result = analysis.anomalies(db, current)
        for row in result.get("results", []):
            db.conn.execute(
                "INSERT INTO anomaly_results VALUES(?,?,?)", (current["id"], row["path"], json.dumps(row))
            )
        db.conn.commit()
        emit(ctx, result)


def recommendations(ctx, db, current, limit):
    model = model_for(ctx)
    rows = []
    for rec in analysis.largest(db, current["id"], limit):
        try:
            live_rec = metadata(Path(rec["path"]), Path(current["root"])).to_dict()
        except OSError:
            continue
        if any(live_rec[k] != rec[k] for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")):
            continue
        rec = live_rec
        safety = assess(rec, live=True).to_dict()
        if not safety["review_eligible"]:
            continue
        ml = predict(model, rec, ctx.obj["allow_demo"]) if model else {"decision": "unknown"}
        row = {
            "path": rec["path"],
            "bytes": rec["size"],
            "safety": safety,
            "ml": ml,
            "action": "Review using owning application/OS cleanup only. DiskLens cannot authorize deletion.",
        }
        rows.append(row)
        for table, payload in [("risk_assessments", safety), ("cleanup_recommendations", row)]:
            db.conn.execute(
                f"INSERT INTO {table} VALUES(?,?,?)", (current["id"], rec["path"], json.dumps(payload))
            )
        if model:
            db.conn.execute(
                "INSERT INTO ml_predictions VALUES(?,?,?,?)",
                (current["id"], rec["path"], model["id"], json.dumps(ml)),
            )
    db.conn.commit()
    rank = {"high": 0, "medium": 1, "low": 2, "retain": 3, "unknown": 4}
    rows.sort(
        key=lambda r: (
            r["ml"]["decision"] != "review_candidate",
            rank.get(r["ml"].get("cleanup_priority_prediction"), 4),
            -r["bytes"],
        )
    )
    return {
        "mode": "read-only review / dry-run",
        "scan": current,
        "largest_files_considered": limit,
        "review_items": rows,
        "ml_review_candidate_bytes": sum(
            r["bytes"] for r in rows if r["ml"]["decision"] == "review_candidate"
        ),
        "guaranteed_recoverable_bytes": None,
        "warning": "Candidate bytes are not verified recoverable space; no deletion is performed.",
    }


@app.command()
@guarded
def cleanup(
    ctx: typer.Context,
    scan_id: str | None = None,
    limit: int = 200,
    dry_run: bool = True,
    execute: bool = False,
):
    """Generate an audited review shortlist. Destructive execution is intentionally disabled."""
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be 1..10000")
    with database(ctx) as db:
        if execute or not dry_run:
            db.audit("execution_refused", {"reason": "Dependency/active-use checks incomplete"})
            raise ValueError(
                "Deletion is disabled in this release. Use supported OS/application cleanup after review."
            )
        current = db.latest(scan_id)
        result = recommendations(ctx, db, current, limit)
        db.audit("dry_run_review", {"scan_id": current["id"], "review_items": len(result["review_items"])})
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            items = result.get("review_items", [])
            console.rule("[bold cyan]Cleanup Review Shortlist (Read-Only)[/bold cyan]")
            if not items:
                console.print("[green]No disposable cleanup candidates identified in the top files.[/green]")
            else:
                t = Table(title=f"Review Candidates ({len(items)} items)", show_lines=False)
                t.add_column("Candidate Path", style="cyan")
                t.add_column("Size", justify="right", style="bold yellow")
                t.add_column("Risk", style="bold")
                t.add_column("Owning App / Context", style="green")
                t.add_column("Recommended Action", style="dim")
                for it in items[:25]:
                    exp = explain(it["path"])
                    t.add_row(
                        it["path"],
                        format_bytes(it["bytes"]),
                        it["safety"]["risk"],
                        exp.get("owner", exp.get("title", "")),
                        exp.get("recommendation", it.get("action", "")),
                    )
                Console().print(t)
                console.print(
                    f"\n[bold]Potential Review Candidates:[/] {len(items)} files | "
                    f"[bold yellow]Candidate Storage:[/] {format_bytes(sum(i['bytes'] for i in items))}\n"
                    f"[dim]Note: DiskLens is read-only. Clean up via owning applications or Windows Settings > System > Storage.[/dim]"
                )
        else:
            emit(ctx, result)


@app.command()
@guarded
def apps(ctx: typer.Context, scan_id: str | None = None):
    """Summarize storage associated with installed applications and developer environments."""
    with database(ctx) as db:
        current = db.latest(scan_id)
        app_data = analyze_application_storage(db, current)
        if ctx.obj["format"] == "terminal" and not ctx.obj.get("output"):
            console.rule("[bold cyan]Application & Developer Storage Analysis[/bold cyan]")
            reg_apps = app_data.get("confirmed_registry_apps", [])
            if reg_apps:
                t1 = Table(title="Confirmed Installed Applications (Windows Registry)", show_lines=False)
                t1.add_column("Application Name", style="bold green")
                t1.add_column("Publisher", style="cyan")
                t1.add_column("Version", style="dim")
                t1.add_column("Storage", justify="right", style="bold yellow")
                for item in reg_apps:
                    t1.add_row(
                        item["name"],
                        item.get("publisher", ""),
                        item.get("version", ""),
                        format_bytes(item["bytes"]),
                    )
                Console().print(t1)

            inferred = app_data.get("inferred_environments", [])
            if inferred:
                t2 = Table(title="Developer Environments & Tool Ecosystems", show_lines=False)
                t2.add_column("Ecosystem", style="bold magenta")
                t2.add_column("Category", style="cyan")
                t2.add_column("Files", justify="right")
                t2.add_column("Storage", justify="right", style="bold yellow")
                t2.add_column("Description", style="dim")
                for env in inferred:
                    t2.add_row(
                        env["name"],
                        env.get("category", ""),
                        f"{env.get('files', 0):,}",
                        format_bytes(env["bytes"]),
                        env.get("description", ""),
                    )
                Console().print(t2)

            if not reg_apps and not inferred:
                console.print("[dim]No confirmed applications or developer environments matched in this scan scope.[/dim]")
        else:
            emit(ctx, app_data)


@app.command()
@guarded
def forecast(ctx: typer.Context, scan_id: str | None = None, capacity: int | None = None):
    """Forecast same-root storage only from adequate multi-day complete-scan history."""
    if capacity is not None and capacity <= 0:
        raise ValueError("capacity must be positive bytes for the scanned scope")
    with database(ctx) as db:
        current = db.latest(scan_id)
        emit(ctx, analysis.forecast(db, current["root"], capacity, current.get("exclusions", "[]")))


@app.command()
@guarded
def compare(ctx: typer.Context, first: str | None = None, second: str | None = None):
    """Compare explicit IDs, or the latest two scans of the latest root."""
    with database(ctx) as db:
        if not first or not second:
            recent = db.conn.execute(
                "SELECT id FROM scans WHERE root=? ORDER BY started DESC LIMIT 2", (db.latest()["root"],)
            ).fetchall()
            if len(recent) < 2:
                raise ValueError("Need two scans of the same root")
            first, second = recent[1][0], recent[0][0]
        emit(ctx, analysis.compare(db, first, second))


@app.command()
@guarded
def report(ctx: typer.Context, scan_id: str | None = None):
    """Full non-hashing report: analysis, categories, anomalies, app hints, forecast and review."""
    with database(ctx) as db:
        current = db.latest(scan_id)
        result = analysis.summary(db, current)
        result.update(
            {
                "categories": get_category_summary(db, current["id"]),
                "anomalies": analysis.anomalies(db, current),
                "applications": analysis.applications(db, current),
                "forecast": analysis.forecast(
                    db, current["root"], exclusions=current.get("exclusions", "[]")
                ),
                "cleanup": recommendations(ctx, db, current, 200),
                "duplicates": "Run duplicates separately to opt into content hashing.",
            }
        )
        emit(ctx, result)


@app.command()
@guarded
def ask(ctx: typer.Context, question: str, scan_id: str | None = None):
    """Ask bounded offline storage questions; unsupported questions explicitly abstain."""
    with database(ctx) as db:
        emit(ctx, answer(db, db.latest(scan_id), question))


@app.command()
@guarded
def explore(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Argument(help="Initial directory to explore")] = None,
):
    """Interactive live explorer: drive selection, index navigation, sort, filter, and file inspect."""
    if not sys.stdin.isatty():
        raise ValueError("Explorer requires an interactive terminal. Use analyze for automation.")

    current = normalize(path) if path else Path.home()
    if not current.exists() or not current.is_dir():
        current = Path.home()

    sort_by, needle = "name", ""
    while True:
        if not current.is_dir() or current.is_symlink():
            current = Path.home()

        entries = []
        scan_error = None
        try:
            with os.scandir(current) as handle:
                for entry in handle:
                    if needle and needle.casefold() not in entry.name.casefold():
                        continue
                    try:
                        rec = metadata(Path(entry.path), current).to_dict()
                        if not rec["is_link"]:
                            entries.append(rec)
                    except OSError:
                        pass
        except OSError as exc:
            scan_error = str(exc)

        # Sorting logic
        if sort_by == "size":
            entries.sort(key=lambda r: (-r["size"], r["name"].casefold()))
        elif sort_by == "type":
            entries.sort(key=lambda r: (not r["is_directory"], r["extension"].casefold(), r["name"].casefold()))
        elif sort_by == "date":
            entries.sort(key=lambda r: (-r.get("mtime_ns", 0), r["name"].casefold()))
        else:
            entries.sort(key=lambda r: (not r["is_directory"], r["name"].casefold()))

        console.rule(f"[bold cyan]Explorer: {current}[/bold cyan]")
        if scan_error:
            console.print(f"[red]Warning reading directory: {scan_error}[/red]")

        table = Table(
            caption=f"Showing {min(len(entries), 100)} of {len(entries)} items (sort: {sort_by}, filter: '{needle or 'none'}')",
            show_lines=False,
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("Type", style="magenta")
        table.add_column("Name", style="bold")
        table.add_column("Size", justify="right", style="green")
        table.add_column("Risk", style="bold")
        table.add_column("Description", style="dim")

        for i, rec in enumerate(entries[:100]):
            r_type = "DIR" if rec["is_directory"] else "FILE"
            r_size = "-" if rec["is_directory"] else format_bytes(rec["size"])
            assessment = assess(rec)
            desc = explain(rec["path"]).get("title", "")
            table.add_row(str(i), r_type, rec["name"], r_size, assessment.risk, desc)

        Console().print(table)
        console.print(
            "[dim]Commands: <#>=enter/inspect | ..=up | drive=switch drive | open <#>=launch | find <text> | sort <name/size/type/date> | q=exit[/dim]"
        )
        choice = typer.prompt("Action", default="..")
        choice = choice.strip()

        if choice == "q":
            break
        elif choice == "..":
            if current.parent != current:
                current = current.parent
        elif choice == "drive":
            d_list = [d for d in get_available_drives() if d.is_ready]
            console.print("\nAvailable drives:")
            for idx, d in enumerate(d_list, 1):
                console.print(f"  {idx}. {d.path} ({d.label or d.drive_type}) — {format_bytes(d.free_bytes)} free")
            d_pick = typer.prompt("Select drive number", default="1")
            if d_pick.isdigit() and 1 <= int(d_pick) <= len(d_list):
                current = Path(d_list[int(d_pick) - 1].path)
        elif choice.startswith("open "):
            idx_str = choice[5:].strip()
            if idx_str.isdigit() and int(idx_str) < len(entries):
                target_p = Path(entries[int(idx_str)]["path"])
                try:
                    if os.name == "nt":
                        os.startfile(str(target_p))
                    else:
                        import subprocess
                        subprocess.Popen(["xdg-open", str(target_p)])
                    console.print(f"[green]Opened {target_p.name} in default application.[/green]")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]Error opening file: {exc}[/red]")
        elif choice.startswith("inspect "):
            idx_str = choice[8:].strip()
            if idx_str.isdigit() and int(idx_str) < len(entries):
                emit(ctx, inspect_path(ctx, Path(entries[int(idx_str)]["path"])))
        elif choice.startswith("sort "):
            sub = choice[5:].strip().lower()
            if sub in ("name", "size", "type", "date"):
                sort_by = sub
        elif choice.startswith("find "):
            needle = choice[5:].strip()
        elif choice == "find":
            needle = ""
        elif choice.isdigit() and int(choice) < len(entries):
            rec = entries[int(choice)]
            if rec["is_directory"]:
                next_dir = Path(rec["path"])
                try:
                    with os.scandir(next_dir):
                        pass
                    current = next_dir
                except OSError as exc:
                    console.print(f"[red]Access denied to {next_dir.name}: {exc}[/red]")
            else:
                emit(ctx, inspect_path(ctx, Path(rec["path"])))


@app.command("train")
@guarded
def train_command(
    ctx: typer.Context,
    dataset: Path,
    out: Annotated[Path, typer.Option()],
    max_risk: float = 0.01,
    min_groups: int = 100,
):
    """Fit category, calibrated safety and priority models; report held-out experiments."""
    if (out / "model.joblib").exists():
        raise ValueError("Use a fresh output directory to preserve reproducibility")
    result = train(load_jsonl(dataset), out, max_risk, min_groups)
    with database(ctx) as db:
        db.conn.execute(
            "INSERT OR REPLACE INTO model_versions VALUES(?,?,?)",
            (result["model_id"], time.time(), json.dumps(result)),
        )
        db.conn.commit()
    emit(ctx, {"artifact_directory": str(out), **result})


@app.command("demo-data")
@guarded
def demo_data(ctx: typer.Context, out: Annotated[Path, typer.Option()], count: int = 180):
    """Create SYNTHETIC wiring-test data, never empirical safety evidence."""
    if not 30 <= count <= 10000:
        raise ValueError("count must be 30..10000 per split")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = demo_dataset(count)
    with out.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    emit(ctx, {"path": str(out), "records": len(rows), "synthetic_demo_only": True})


@app.command("dataset-export")
@guarded
def dataset_export(
    ctx: typer.Context,
    out: Annotated[Path, typer.Option()],
    device_id: Annotated[str, typer.Option()],
    user_id: Annotated[str, typer.Option()],
    split: Annotated[str, typer.Option()],
    scan_id: str | None = None,
    hash_content: bool = False,
):
    """Export private metadata for annotation. Hashing all files requires --hash-content."""
    from .ml.features import features

    if split not in {"train", "calibration", "policy", "test"}:
        raise ValueError("Invalid split")
    out.parent.mkdir(parents=True, exist_ok=True)
    with database(ctx) as db, out.open("x", encoding="utf-8") as handle:
        current = db.latest(scan_id)
        count = 0
        for rec in db.records(current["id"]):
            sha, error = None, None
            if hash_content:
                try:
                    sha = digest(
                        rec["path"], [rec[k] for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")]
                    )
                except (ValueError, OSError) as exc:
                    error = str(exc)
            row = {
                **rec,
                "record_id": f"{current['id']}-{count}",
                "device_id": device_id,
                "user_id": user_id,
                "split": split,
                "sha256": sha,
                "hash_error": error,
                "related_group": "",
                "label": "unknown",
                "evidence": "",
                "category": "unknown",
                "priority": "unknown",
                "modified_days": features(rec)["modified_days"],
            }
            handle.write(json.dumps(row) + "\n")
            count += 1
    emit(
        ctx,
        {
            "records": count,
            "path": str(out),
            "next": "PRIVATE paths. Annotate independently, establish related-file groups and content hashes "
            "before training. Blank evidence/groups intentionally fail validation.",
        },
    )


@app.command("annotations")
@guarded
def annotations(
    ctx: typer.Context,
    first: Path,
    second: Path,
    adjudications: Path | None = None,
    dataset: Path | None = None,
    out: Path | None = None,
):
    """Measure independent agreement; unresolved conflicts become unknown. Optionally merge dataset."""
    result = reconcile(
        load_jsonl(first), load_jsonl(second), load_jsonl(adjudications) if adjudications else []
    )
    if dataset:
        if out is None:
            raise ValueError("--out is required with --dataset")
        resolved = {r["record_id"]: r for r in result["resolved"]}
        rows = load_jsonl(dataset)
        if {r["record_id"] for r in rows} != set(resolved):
            raise ValueError("Dataset and annotations must contain the exact same record IDs")
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8") as handle:
            for row in rows:
                resolution = resolved[row["record_id"]]
                row.update(
                    {
                        "label": resolution["label"],
                        "evidence": json.dumps(resolution),
                        "annotation_resolution": resolution,
                    }
                )
                handle.write(json.dumps(row) + "\n")
        result["merged_dataset"] = str(out)
    emit(ctx, result)


@app.command("benchmark")
@guarded
def benchmark_command(
    ctx: typer.Context, path: Path, query_cases: Annotated[Path, typer.Option()], repeats: int = 3
):
    """Measure scan/query latency and intent accuracy on an explicitly supplied question set."""
    from .benchmark import benchmark

    with database(ctx) as db:
        emit(ctx, benchmark(db, normalize(path), query_cases, repeats, ctx.obj["exclude"]))


def interactive(ctx):
    """Interactive command-line menu."""
    while True:
        console.rule("[bold cyan]DISKLENS — Intelligent Disk Analyzer (Read-Only)[/bold cyan]")
        try:
            drives_list = get_available_drives()
            scannable = [d for d in drives_list if d.is_ready]
            if scannable:
                drive_summary = " | ".join(
                    f"{d.path} {render_bar(d.used_bytes, d.total_bytes, width=10)} {format_bytes(d.free_bytes)} free"
                    for d in scannable[:3]
                )
                console.print(f"[bold]Drives:[/] {drive_summary}")
        except Exception:  # noqa: BLE001, S110
            pass

        console.print("\n[bold]Select an action:[/bold]")
        menu_items = [
            ("Discover & View Drives", drives),
            ("Scan a Drive or Directory", scan),
            ("Scan Entire Computer (--all)", "scan_all"),
            ("Explore Files and Folders", explore),
            ("Analyze Storage & Categories", analyze),
            ("Directory Size Hierarchy Tree", tree),
            ("Find Largest Files", largest),
            ("Find Duplicate Files", duplicates),
            ("Identify Cleanup Opportunities", cleanup),
            ("Understand File or Folder", inspect),
            ("Application Storage Inventory", apps),
            ("Storage Forecast & History", forecast),
            ("Generate Full Report", report),
        ]
        for i, (name, _) in enumerate(menu_items, 1):
            console.print(f" {i:2}. {name}")
        console.print("  0. Exit")

        choice = typer.prompt("\nChoose option", default="0").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(menu_items)):
            continue

        target = menu_items[int(choice) - 1][1]
        try:
            if target == "scan_all":
                scan(ctx, path=None, all=True)
            elif target == scan:
                path_input = typer.prompt("Enter directory or drive path to scan", default=str(Path.home()))
                p = resolve_user_path(path_input) if path_input.strip() else Path.home()
                scan(ctx, path=p, all=False)
            elif target == explore:
                path_input = typer.prompt("Enter path", default=str(Path.home()))
                p = resolve_user_path(path_input)
                explore(ctx, path=p)
            elif target in (inspect, risk):
                path_input = typer.prompt("Enter path", default=str(Path.home()))
                p = resolve_user_path(path_input)
                target(ctx, path=p)
            elif target == tree:
                path_input = typer.prompt("Enter root directory for size tree (or press Enter for latest scan)", default="")
                p = resolve_user_path(path_input) if path_input.strip() else None
                tree(ctx, path=p)
            elif target in (analyze, largest, duplicates, anomalies, categories):
                path_input = typer.prompt("Enter path (or press Enter for latest scan)", default="")
                p = resolve_user_path(path_input) if path_input.strip() else None
                target(ctx, path=p)
            else:
                target(ctx)
        except (typer.Exit, KeyboardInterrupt):

            console.print("[dim]Operation completed or cancelled.[/dim]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Error: {exc}[/red]")


if __name__ == "__main__":
    app()
