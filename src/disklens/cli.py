"""CLI-first DiskLens. All filesystem analysis is non-destructive."""

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
from .database import Database
from .duplicates import digest, find_duplicates
from .knowledge import category_rule, explain
from .ml.data import demo_dataset, load_jsonl, reconcile
from .ml.training import load_model, predict, train
from .query import answer
from .safety import assess
from .scanner import metadata

app = typer.Typer(
    help="DiskLens: offline, risk-aware filesystem intelligence. Read-only analysis.", no_args_is_help=False
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
    else:
        text = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False)
        if fmt == "html":
            text = (
                '<!doctype html><meta charset="utf-8"><title>DiskLens report</title><h1>DiskLens</h1><pre>'
                + html.escape(text)
                + "</pre>"
            )
    output = ctx.obj["output"]
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="") as handle:
            handle.write(text + "\n")
        console.print(f"Created {output}", markup=False)
    elif fmt == "terminal":
        # Rich formatting, with escaping disabled for untrusted path text.
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
        result["ml"] = {"decision": "unknown", "reason": "No trained model loaded. Rules are not ML."}
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
def scan(
    ctx: typer.Context,
    path: Path,
    exclude: Annotated[
        list[str] | None, typer.Option(help="Repeat glob patterns, matched to names or relative paths.")
    ] = None,
):
    """Stream directory/drive metadata into SQLite. Ctrl+C saves a cancelled scan."""
    with database(ctx) as db:
        progress = (lambda n: console.print(f"{n:,} files scanned")) if ctx.obj["verbose"] else None
        emit(ctx, db.scan(normalize(path), list(ctx.obj["exclude"]) + (exclude or []), progress))


def selected(ctx, db, path=None, scan_id=None):
    if path is not None:
        return db.scan(normalize(path), ctx.obj["exclude"])
    return db.latest(scan_id)


@app.command()
@guarded
def analyze(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Scan a supplied path, or analyze a saved scan (latest by default)."""
    with database(ctx) as db:
        emit(ctx, analysis.summary(db, selected(ctx, db, path, scan_id)))


@app.command()
@guarded
def inspect(ctx: typer.Context, path: Path, deep: bool = False):
    """Explain a live path; --deep opts into reading at most 32 header bytes of a file."""
    result = inspect_path(ctx, path)
    if deep and not result["facts"]["is_directory"]:
        from .identification import identify

        result["format_inspection"] = identify(normalize(path))
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
        emit(ctx, analysis.largest(db, current["id"], limit))


@app.command()
@guarded
def duplicates(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Opt into hashing same-size candidates and verifying bytes. Never delete copies."""
    with database(ctx) as db:
        current = selected(ctx, db, path, scan_id)
        emit(ctx, {"scan": current, **find_duplicates(db, current["id"])})


@app.command()
@guarded
def anomalies(ctx: typer.Context, path: Path | None = None, scan_id: str | None = None):
    """Fit Isolation Forest on directory metadata (no anomaly => deletion inference)."""
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
    # Limit expensive inference; this is explicitly a largest-file review shortlist.
    for rec in analysis.largest(db, current["id"], limit):
        # Refresh live metadata before producing a review shortlist from historical facts.
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
        emit(ctx, result)


@app.command()
@guarded
def apps(ctx: typer.Context, scan_id: str | None = None):
    """Summarize application/developer storage by path hints, not installed-app verification."""
    with database(ctx) as db:
        emit(ctx, analysis.applications(db, db.latest(scan_id)))


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
    """Full non-hashing report: analysis, anomalies, app hints, forecast and review."""
    with database(ctx) as db:
        current = db.latest(scan_id)
        result = analysis.summary(db, current)
        result.update(
            {
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
def explore(ctx: typer.Context, path: Path):
    """Interactive live explorer: index navigation, parent, sort, filter, search, inspect."""
    if not sys.stdin.isatty():
        raise ValueError("Explorer requires an interactive terminal. Use analyze for automation.")
    current = normalize(path)
    sort_by, needle = "name", ""
    while True:
        if not current.is_dir() or current.is_symlink():
            raise ValueError("Explorer requires a real directory")
        entries = []
        with os.scandir(current) as handle:
            for entry in handle:
                if needle.casefold() not in entry.name.casefold():
                    continue
                try:
                    rec = metadata(Path(entry.path), current).to_dict()
                    if not rec["is_link"]:
                        entries.append(rec)
                except OSError as exc:
                    console.print(str(exc), markup=False)
        entries.sort(
            key=lambda r: (
                (-r["size"], r["name"])
                if sort_by == "size"
                else (not r["is_directory"], r["name"].casefold())
            )
        )
        table = Table(
            title=str(current), caption="Directory entry sizes are NOT subtree sizes; use analyze for totals."
        )
        for title in ("#", "Name", "Type", "Bytes", "Risk"):
            table.add_column(title)
        for i, rec in enumerate(entries[:200]):
            from rich.text import Text

            table.add_row(
                str(i),
                Text(rec["name"]),
                "dir" if rec["is_directory"] else "file",
                str(rec["size"]),
                assess(rec).risk,
            )
        console.print(table)
        choice = typer.prompt("index to open/inspect | .. | sort name/size | find text | q")
        if choice == "q":
            break
        if choice == "..":
            current = current.parent
        elif choice.startswith("sort "):
            sort_by = choice[5:]
        elif choice.startswith("find "):
            needle = choice[5:]
        elif choice.isdigit() and int(choice) < min(len(entries), 200):
            rec = entries[int(choice)]
            if rec["is_directory"]:
                current = Path(rec["path"])
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
    options = [
        ("Analyze Drive", analyze),
        ("Explore Directories", explore),
        ("Find Largest Files", largest),
        ("Explain File or Folder", inspect),
        ("Analyze Deletion Risk", risk),
        ("Find Duplicate Files", duplicates),
        ("Detect Storage Anomalies", anomalies),
        ("Storage Breakdown", analyze),
        ("Cleanup Recommendations", cleanup),
        ("Application Storage", apps),
        ("Storage Forecast", forecast),
        ("Generate Full Report", report),
    ]
    while True:
        console.rule("DISKLENS · AI-POWERED STORAGE ANALYZER · READ ONLY")
        import shutil

        usage = shutil.disk_usage(Path.home())
        console.print(
            f"Home volume: {usage.used / 2**30:.1f} GiB used / {usage.total / 2**30:.1f} GiB; "
            f"{usage.free / 2**30:.1f} GiB free. Choose a path to analyze."
        )
        for i, (name, _) in enumerate(options, 1):
            console.print(f"{i:2}. {name}")
        choice = typer.prompt("0. Exit | Choose option", default="0")
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(options):
            continue
        fn = options[int(choice) - 1][1]
        try:
            if fn in (analyze, explore, largest, inspect, risk, duplicates, anomalies):
                ctx.invoke(fn, path=Path(typer.prompt("Path")))
            else:
                ctx.invoke(fn)
        except (typer.Exit, KeyboardInterrupt):
            console.print("Operation stopped.")


if __name__ == "__main__":
    app()
