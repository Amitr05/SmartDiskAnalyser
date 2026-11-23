# Implementation status and boundaries

This is the first working DiskLens research release built from an empty repository. The original product direction is retained. Features not yet verified are not presented as complete.

## Available now

- Installable Python package, Typer/Rich CLI, interactive menu/explorer, all primary command names.
- Native Windows drive discovery (`drives` command) using Win32 API (`GetLogicalDrives`, `GetDriveTypeW`, `GetVolumeInformationW`, `shutil.disk_usage`) with volume labels, filesystem names, total/used/free capacity, and visual storage bars.
- Multi-drive and whole-computer scanning (`scan --all`) with automatic volume discovery, link/junction protections, and error tolerance across volumes.
- Terminal storage visualizations: visual usage bars (`render_bar`), recursive directory size hierarchy trees (`tree` command), and high-level category summaries (`categories` command) with 9 standard categories.
- Windows Registry application discovery (`apps` command) querying 64-bit and 32-bit `winreg` uninstall keys across HKLM and HKCU, paired with developer toolchain footprint detection.
- Expanded offline knowledge base (`inspect` command) explaining Windows system components (System32, SysWOW64, SoftwareDistribution, WinSxS, DeliveryOptimization, System Volume Information, Recovery, Recycle Bin), major applications (Chrome, Edge, Steam), and developer ecosystems (npm, pip, venv, vscode, wsl, docker).
- Upgraded interactive CLI explorer (`explore` command) featuring drive selection, index-based folder navigation, formatted sizes, sorting by size/name, filename filtering, and file inspection/opening.
- Standalone styled HTML report generation (`report` command / `--format html`) with clean, modern CSS, storage bars, and structured tables.
- Streamed non-following metadata traversal into SQLite, cancellation/error states, configurable exclusions, logical/unique/allocated-size distinction and volume measurements.
- Size-grouped SHA-256 duplicate detection with NTFS timestamp jitter normalization, scan identity checks and subsequent byte comparison; no name/size-only duplicate claims.
- Independent deterministic protection and live Windows Resource Protection API wrapper; unknown/native checks remain explicitly unknown.
- Actual category, calibrated safety and review-priority Random-Forest training, feature engineering, artifact persistence, loaded-model inference and seed/version/dataset manifests.
- Four-way user/device/hash/related-group split validation, independent-annotation agreement/reconciliation tools.
- Fixed-grid approximate group-aware abstention selection, unsupported-context withholding, protected-file veto and synthetic-model recommendation block.
- Rule, Decision Tree and ordinary Random-Forest baselines; offline no-veto/no-abstention/no-calibration/no-controls experiments and safety metrics.
- Per-scan learned Isolation-Forest directory anomalies, application path hints, sufficient-history-only temporal regression with measured expanding-window errors.
- Read-only review shortlists, audit log, hard refusal of deletion execution.
- Automated unit/integration tests covering Windows APIs, drives, visualizations, registry apps, CLI commands, scanner, duplicates, ML, and safety.

## Not yet implemented / not yet established

- **No real labelled Windows dataset or trained, validated deployment model.** Demo generation/training is reproducible and genuinely learns, but synthetic results do not count as research evidence.
- **No real independent annotator agreement or cross-device study results.** The tools and protocol exist; the participants/data do not yet.
- No active-use/process/service dependency enumeration, verified owner intent, Authenticode verification, or Windows low-level allocated-size API (`FSCTL_GET_RETRIEVAL_POINTERS`). These fields are not silently assumed safe/false.
- No destructive executor, Recycle Bin integration or application-specific cleanup procedure invocation. Every cleanup is analysis-only. LOW RISK is reserved for future validated cases and is not currently emitted.
- No recursive folder deletion, automatic removal, forced overrides, natural-language shell execution or LLM API dependency.
- No perceptual media near-duplicate discovery. Related-group leakage prevention checks supplied grouping IDs; manual/provenance grouping quality remains a study responsibility.
- No trained directory-purpose classifier. Directory explanations use KB context/aggregates; file ML is not evidence of a directory's contents.
- No incremental filesystem change-journal scanner, compressed/sparse Windows allocation accounting, or atomic scan snapshot.
- No Docker volume deletion, Docker API inspection, historical anomaly model, persistent anomaly/forecast estimator artifact, learned-to-rank objective or rank-quality study.
- No claimed hyperparameter search, XGBoost comparison, large-data out-of-core training, device-bootstrap CIs, calibrated forecasting intervals or independent chatbot-accuracy evidence.
- Metadata/reporting bounds are explicit: directory aggregation uses O(number of directories), duplicate results retain candidate groups, supervised training loads its dataset into memory, and cleanup considers a bounded largest-file shortlist.

## Database implementation

Implemented tables: `scans`, `files` (including directory metadata), `scan_errors`, `storage_history`, `model_versions`, `ml_predictions`, `risk_assessments`, `anomaly_results`, `cleanup_recommendations`, `cleanup_operations`. Scan rows carry full-volume measurements and exclusion scope. Category/model results are JSON with version references; application summaries and directory totals are derived rather than placed in empty placeholder tables. Full production schema normalization, retention controls and migrations beyond the initial additive fields remain future work.

## Validation performed in this environment

- **102 passed, 5 skipped, 0 failed** in pytest on Windows 11 (Python 3.11.16).
- Ruff static checks and formatting passed across all source and test modules.
- CLI smoke check verified across all commands: `drives`, `scan`, `analyze`, `tree`, `categories`, `apps`, `inspect`, `duplicates`, `cleanup`, `report`.
- Windows Registry integration verified on live host registry (reading installed apps safely).
- Windows API volume enumeration verified on live host filesystem.
- Synthetic four-cohort dataset training, calibration, and persistence tested.
- Read-only safety fail-closed verification tested (`cleanup --execute` fails closed).

## Next implementation/study gates

1. Run the Windows matrix and disposable Windows VM safety/ACL/junction/long-path tests.
2. Collect consented, independently annotated, grouped cohorts following the resubmission documents.
3. Train/freeze models and report real device-level safety/coverage tradeoffs and uncertainty.
4. Add audited application-specific/native validation only where justified; keep unknowns as unknown.
5. Consider any future explicit-confirmation execution stage only after separate safety review. Publication readiness depends on defensible novelty/prior-work comparison and empirical evidence, not the number of features.
