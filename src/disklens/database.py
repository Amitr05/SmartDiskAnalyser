"""SQLite-backed streaming scans and historical metadata; no file contents stored."""

import json
import shutil
import sqlite3
import time
import uuid
from pathlib import Path

from .scanner import walk

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, root TEXT NOT NULL, started REAL, elapsed REAL,
 status TEXT, file_count INTEGER DEFAULT 0, logical_bytes INTEGER DEFAULT 0,
 unique_bytes INTEGER DEFAULT 0, allocated_bytes INTEGER, error_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
 scan_id TEXT, path TEXT, parent TEXT, size INTEGER, device TEXT, inode TEXT,
 is_directory INTEGER, extension TEXT, metadata TEXT,
 PRIMARY KEY(scan_id,path), FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS files_size ON files(scan_id,size);
CREATE INDEX IF NOT EXISTS files_parent ON files(scan_id,parent);
CREATE TABLE IF NOT EXISTS scan_errors (scan_id TEXT, path TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS storage_history (scan_id TEXT PRIMARY KEY, root TEXT, timestamp REAL, bytes INTEGER);
CREATE TABLE IF NOT EXISTS model_versions (id TEXT PRIMARY KEY, created REAL, details TEXT);
CREATE TABLE IF NOT EXISTS ml_predictions (scan_id TEXT, path TEXT, model_id TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS risk_assessments (scan_id TEXT, path TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS anomaly_results (scan_id TEXT, path TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS cleanup_recommendations (scan_id TEXT, path TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS cleanup_operations (timestamp REAL, action TEXT, details TEXT);
"""


class Database:
    def __init__(self, path: Path):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            fallback = Path.cwd() / ".disklens" / path.name
            fallback.parent.mkdir(parents=True, exist_ok=True)
            path = fallback
        self.path = path.absolute()
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        columns = {r[1] for r in self.conn.execute("PRAGMA table_info(scans)")}
        if "exclusions" not in columns:
            self.conn.execute("ALTER TABLE scans ADD COLUMN exclusions TEXT DEFAULT '[]'")
        for name in ("volume_total", "volume_free", "volume_used"):
            if name not in columns:
                self.conn.execute(f"ALTER TABLE scans ADD COLUMN {name} INTEGER")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.commit()

    def close(self):
        self.conn.close()

    def latest(self, scan_id=None):
        if scan_id:
            row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        else:
            row = self.conn.execute("SELECT * FROM scans ORDER BY started DESC LIMIT 1").fetchone()
        if row is None:
            raise ValueError("No scan found. Run disklens scan <directory> first.")
        return dict(row)

    def records(self, scan_id, files_only=True):
        query = "SELECT metadata FROM files WHERE scan_id=?"
        if files_only:
            query += " AND is_directory=0"
        for row in self.conn.execute(query, (scan_id,)):
            yield json.loads(row[0])

    def scan(self, root: Path, exclude=(), progress=None):
        root = root.absolute()
        # Validate before opening a scan transaction.
        if not root.is_dir():
            raise ValueError(f"Not a directory: {root}")
        scan_id = uuid.uuid4().hex
        started = time.time()
        clock = time.perf_counter()
        usage = shutil.disk_usage(root)
        self.conn.execute(
            "INSERT INTO scans(id,root,started,status) VALUES(?,?,?,?)",
            (scan_id, str(root), started, "running"),
        )
        self.conn.execute(
            "UPDATE scans SET volume_total=?,volume_free=?,volume_used=? WHERE id=?",
            (usage.total, usage.free, usage.used, scan_id),
        )
        self.conn.commit()
        count = errors = 0

        def error(path, message):
            nonlocal errors
            errors += 1
            self.conn.execute("INSERT INTO scan_errors VALUES(?,?,?)", (scan_id, path, message))

        excludes = list(exclude)
        # Avoid scanning the live database and its journal, including default state.
        try:
            rel = self.path.relative_to(root).as_posix()
            excludes.extend([rel, rel + "-wal", rel + "-shm", rel + "-journal"])
        except ValueError:
            pass
        scope = json.dumps(sorted(set(excludes)))
        self.conn.execute("UPDATE scans SET exclusions=? WHERE id=?", (scope, scan_id))
        status = "complete"
        try:
            for rec in walk(root, excludes, error):
                self.conn.execute(
                    "INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        scan_id,
                        rec.path,
                        rec.parent,
                        rec.size,
                        str(rec.device),
                        str(rec.inode),
                        rec.is_directory,
                        rec.extension,
                        json.dumps(rec.to_dict()),
                    ),
                )
                count += not rec.is_directory
                if count and count % 500 == 0:
                    self.conn.commit()
                    if progress:
                        progress(count)
        except KeyboardInterrupt:
            status = "cancelled"
        except (OSError, ValueError) as exc:
            error(str(root), str(exc))
            status = "failed"
        # Logical path totals and unique inode totals are deliberately distinct.
        logical = self.conn.execute(
            "SELECT COALESCE(SUM(size),0) FROM files WHERE scan_id=? AND is_directory=0", (scan_id,)
        ).fetchone()[0]
        unique = self.conn.execute(
            """SELECT COALESCE(SUM(size),0) FROM
            (SELECT MAX(size) AS size FROM files WHERE scan_id=? AND is_directory=0 GROUP BY device,inode)""",
            (scan_id,),
        ).fetchone()[0]
        allocated = 0
        for row in self.conn.execute(
            """SELECT metadata FROM files WHERE scan_id=? AND is_directory=0
                                        GROUP BY device,inode""",
            (scan_id,),
        ):
            value = json.loads(row[0])["allocated"]
            if value is None:
                allocated = None
                break
            allocated += value
        elapsed = time.perf_counter() - clock
        if errors and status == "complete":
            status = "partial"
        self.conn.execute(
            """UPDATE scans SET status=?,elapsed=?,file_count=?,logical_bytes=?,
                             unique_bytes=?,allocated_bytes=?,error_count=? WHERE id=?""",
            (status, elapsed, count, logical, unique, allocated, errors, scan_id),
        )
        if status == "complete":
            self.conn.execute(
                "INSERT INTO storage_history VALUES(?,?,?,?)", (scan_id, str(root), started, unique)
            )
        self.conn.commit()
        return self.latest(scan_id)

    def audit(self, action, details):
        self.conn.execute(
            "INSERT INTO cleanup_operations VALUES(?,?,?)", (time.time(), action, json.dumps(details))
        )
        self.conn.commit()
