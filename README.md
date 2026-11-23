# DiskLens

**AI-assisted, CLI-first filesystem intelligence with conservative, risk-aware recommendations.**

Project: *AI-Assisted Disk Analyzer: Learning-Based Safe-to-Delete File Classification with Natural-Language Storage Queries*
Team: **Amit Ravi Mishra, Abhishek, Naren**

DiskLens keeps the original smart-filesystem-assistant idea: understand storage, explain known directory purposes, classify files with ML, find verified duplicates, flag anomalies, forecast growth, and help users investigate cleanup opportunities. There is **no GUI, web server, cloud dependency, or required LLM**.

**Release status: working research prototype (0.1), not a certified cleanup utility.** It is Windows-first in path/safety policy and has portable scanning for development. Local validation was performed on Linux; Windows CI is configured but Windows execution has not been verified in this environment. Independent-device research results and real annotator agreement are **not yet available**. See [implementation status](docs/STATUS.md).

## Safety comes first

- Filesystem analysis is **read-only**. DiskLens writes only its own SQLite state and explicitly requested exports/model artifacts. File reads may update filesystem access timestamps; this is not a forensic acquisition tool.
- Protected Windows locations, system attributes, live Windows Resource Protection results, links, application installations/state, personal data and unknown dependencies cannot be overridden by ML.
- Predictions are labelled as predictions. File category, large size, old age, duplicate content and anomaly status **do not establish deletion safety**.
- A calibrated safety classifier can abstain. With insufficient policy-validation evidence, **no threshold is enabled**. An unsupported feature context also abstains.
- “Review candidate” means **investigate through the owning application's/Windows' supported tools**, not “safe to delete.” There are no unconditional safety guarantees.
- **Deletion execution is deliberately disabled**, including `cleanup --execute` and `cleanup --no-dry-run`. Refusals and review operations are audited. An unsafe implementation hidden behind a confirmation prompt would not satisfy the project's safety objective.
- Only load **trusted, locally trained** `.joblib` artifacts: pickle/joblib loading can execute code.

## Install

Python **3.11+**. Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,windows]"
disklens --help
```

Linux/macOS development:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

For the exact locally tested dependency versions, install `requirements-dev.lock`, then `python -m pip install -e . --no-deps`. The lock records the Linux/CPython 3.11 environment; Windows-specific extras are separate.

No administrator privileges are needed for ordinary scans. Permission failures are recorded rather than suppressed. Windows native WRP uses `ctypes`; `pywin32` is optional for future integrations. XGBoost/Matplotlib are optional extras, not silently claimed as implemented models.

## Start using it

PowerShell examples (quote paths with spaces):

```powershell
disklens                                      # interactive menu in a real terminal
disklens scan 'C:\Users\YourName\Downloads'
disklens analyze                              # latest saved scan
disklens analyze 'C:\Users\YourName'           # scan, then analyze
disklens scan C: --exclude '.git' --exclude '.venv'
disklens largest --limit 20
disklens inspect 'C:\Windows\System32'
disklens inspect 'C:\Users\YourName\Downloads\file.bin' --deep
disklens risk 'C:\Users\YourName\AppData\Local\Temp\file.tmp'
disklens duplicates                           # explicit content hashing opt-in
disklens anomalies
disklens cleanup --dry-run                     # review only, never removes anything
disklens apps
disklens compare                               # latest two same-root scans
disklens forecast                              # refuses inadequate history
disklens ask "Which files take the most storage?"
disklens explore 'C:\Users\YourName'
disklens report
```

Global options go **before** the command:

```powershell
disklens --format json scan 'C:\Users\YourName\Downloads'
disklens --format csv --output artifacts/largest.csv largest
disklens --format html --output artifacts/report.html report
disklens --config examples/disklens.toml --verbose scan C:
disklens --db artifacts/study.sqlite analyze .
```

Existing report/export files are not overwritten. HTML is a static report, not an application. Nested CSV fields contain JSON; spreadsheet formula prefixes are escaped. `--scan-id <id>` selects a saved scan for most analysis commands. `compare --first <id> --second <id>` compares explicit same-root, same-exclusion snapshots.

### Natural-language queries

`ask` is a bounded, offline **deterministic intent router over scan facts**, not an LLM or a novel ML contribution. It supports largest files, summary, application hints, anomalies, forecast, duplicate-command guidance and safety guidance. Unsupported questions explicitly abstain. It does not infer who created an unfamiliar file, invent dependencies, execute shell commands, or authorize deletion.

### What a scan measures

SQLite stores streamed metadata, not file contents. Scans do not hash files. Symlinks, junctions/reparse points, mount boundaries and special files are skipped and reported; exclusions are recorded as part of the scan scope. Logical path bytes, unique-inode bytes, physical allocation (when available), and full-volume utilization are separate quantities. Windows physical allocation is currently **unknown**, not estimated as logical bytes. `ctime` is platform metadata-change time, not a portable creation timestamp; access time is recorded but not treated as reliable usage evidence.

Scans may be `complete`, `partial`, `cancelled` or `failed`. Complete means complete **within the declared exclusions**, not an atomic snapshot or an assertion of global filesystem visibility. Only complete scans feed forecasts. Each scan is a new snapshot; incremental reuse is not yet implemented.

## Genuine ML, not a chatbot wrapper

| Component | Implemented learning/inference |
|---|---|
| File purpose/category | Random Forest over engineered metadata; low-confidence/unseen-context output is unknown |
| Conservative safety research model | Separate Random Forest, sigmoid probability calibration on held-out devices, independently selected abstention policy |
| Cleanup review priority | Separate supervised Random Forest trained on explicit high/medium/low/retain/unknown labels; ranks bounded review shortlists |
| Storage anomalies | Isolation Forest fitted to directory aggregates; flags relative structural outliers, not disposable files |
| Storage forecast | Linear Regression on same-root/same-exclusion daily histories, with expanding-window backtests and descriptive error bands |
| Non-learned safety engine | Independent veto before/after inference; never weakened by CLI flags |

Training artifacts include `model.joblib`, `evaluation.json` and `manifest.json`. Anomaly models are fitted per scan and forecasting models per adequate history; these two estimators are transient and reproducible from stored observations, not distributed pretrained models. Dataset/model directories are intentionally not committed.

### Reproduce the synthetic demonstration

```sh
mkdir -p artifacts
# PowerShell: New-Item -ItemType Directory -Force artifacts
disklens demo-data --out artifacts/demo.jsonl --count 180
disklens --db artifacts/demo.sqlite train artifacts/demo.jsonl --out artifacts/demo-model
disklens --model artifacts/demo-model/model.joblib --allow-demo inspect README.md
```

This actually trains, calibrates, evaluates and persists models. Synthetic examples have deliberately simplified patterns and some noise. **They cannot validate real safety, novelty or cross-device performance.** Synthetic artifacts are blocked from generating live ML review recommendations even with `--allow-demo`. The default 1% policy-risk target may yield total abstention on small datasets; that is intentional, not a reason to weaken controls. Do not relabel synthetic devices as real devices.

### Real data workflow

1. Read the [annotation protocol](docs/ANNOTATION_PROTOCOL.md) and obtain informed consent. Keep exports private.
2. Collect separate fitting, calibration, policy-selection and test cohorts. Device **and user** identities must be disjoint; this requires at least four users/devices. More independent users/devices are needed for credible research.
3. Export each cohort's scans. Hashing is an explicit opt-in because it reads all exported files:

```sh
disklens dataset-export --out artifacts/raw-train.jsonl --device-id machine-A --user-id owner-A --split train --hash-content
```

4. Create independent annotation JSONL files; establish related-file groups (project/version/snapshot/template families) across **all cohorts before splitting**. Blank evidence, hashes or groups intentionally block training. Remove cross-device duplicate families from all but one partition, or revise cohort assignment; never just change their IDs.
5. Reconcile labels and inspect agreement:

```sh
disklens annotations artifacts/annotator-a.jsonl artifacts/annotator-b.jsonl --dataset artifacts/raw-train.jsonl --out artifacts/labelled-train.jsonl
# Optional: --adjudications artifacts/adjudicator.jsonl
```

6. Independently label category and review priority, combine the four labelled cohort JSONL files, then train into a **fresh** directory:

```sh
disklens train artifacts/study.jsonl --out artifacts/study-model
# After reviewing held-out evidence:
disklens --model artifacts/study-model/model.joblib cleanup --dry-run
```

See [methodology](docs/METHODOLOGY.md) for feature/schema details, threshold selection and the distinction between a conventional classifier and risk-aware selective decisions. No model is supplied as validated for real deletion decisions.

## Measure, do not invent results

```sh
disklens --format json --output artifacts/benchmark.json benchmark . --query-cases examples/query-cases.jsonl --repeats 3
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
```

`benchmark` records actual scan/query timings, platform, scan status and intent accuracy. The bundled questions are a **development smoke set**, not an independent chatbot benchmark. Repeated scans are warm/mixed-cache. Use a separate question set, realistic drives, multiple machines and the [evaluation plan](docs/EVALUATION_PLAN.md) before reporting research results.

Training reports include safe-class precision, important→safe false-safe rate, unsafe/unknown recommendations, recommendation coverage, abstention, category metrics, calibrated-safe Brier score/ROC-AUC when defined, inference latency, rule/tree/Random-Forest baselines and offline control ablations. Undefined metrics are `null`, never fake perfect scores.

## Layout

```text
src/disklens/
  cli.py                Typer/Rich commands, interactive menu and explorer
  scanner.py records.py streamed traversal and metadata
  database.py           scan snapshots, history, predictions and audit trail
  analysis.py           aggregates, applications, anomalies, forecast, comparison
  duplicates.py         selective SHA-256 and byte verification
  identification.py     optional bounded magic-byte inspection
  knowledge.py          curated Windows/developer directory explanations
  safety.py             deterministic, live-aware vetoes
  query.py benchmark.py grounded offline routing and measurement
  ml/
    features.py         auditable metadata feature engineering
    data.py             annotation reconciliation and leakage checks
    policy.py           abstention threshold and safety metrics
    training.py         actual training, calibration, evaluation and inference
```

## Before calling this production-ready

There is no arbitrary recursive deletion, actual deletion API, signed-file verification, process/dependency inventory, installed-application registry inventory, Docker API integration, near-media duplicate detection, or validated Windows cleanup execution. Directory explanations use curated context and aggregates rather than a falsely claimed trained directory classifier. Application reports are path hints. Forecasts require at least five distinct dates spanning seven days and are scope-specific, not promises of future free space. More details and implementation gates are in [STATUS.md](docs/STATUS.md).

**Faculty revision documents:** [methodology](docs/METHODOLOGY.md) · [annotation protocol](docs/ANNOTATION_PROTOCOL.md) · [evaluation plan](docs/EVALUATION_PLAN.md). This repository supports executing the revised study; it does not claim the study has already established publication readiness.
