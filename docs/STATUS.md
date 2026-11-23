# Implementation status and boundaries

This is the first working DiskLens research release built from an empty repository. The original product direction is retained. Features not yet verified are not presented as complete.

## Available now

- Installable Python package, Typer/Rich CLI, interactive menu/explorer, all primary command names.
- Streamed non-following metadata traversal into SQLite, cancellation/error states, configurable exclusions, logical/unique/allocated-size distinction and volume measurements.
- Saved snapshots, extension breakdown, largest files/directories, changes between same-root/same-exclusion scans.
- Size-grouped SHA-256 duplicate detection, scan identity checks and subsequent byte comparison; no name/size-only duplicate claims.
- Offline Windows/developer knowledge context and bounded optional header inspection.
- Independent deterministic protection and live Windows Resource Protection API wrapper; unknown/native checks remain explicitly unknown.
- Actual category, calibrated safety and review-priority Random-Forest training, feature engineering, artifact persistence, loaded-model inference and seed/version/dataset manifests.
- Four-way user/device/hash/related-group split validation, independent-annotation agreement/reconciliation tools.
- Fixed-grid approximate group-aware abstention selection, unsupported-context withholding, protected-file veto and synthetic-model recommendation block.
- Rule, Decision Tree and ordinary Random-Forest baselines; offline no-veto/no-abstention/no-calibration/no-controls experiments and safety metrics.
- Per-scan learned Isolation-Forest directory anomalies, application path hints, sufficient-history-only temporal regression with measured expanding-window errors.
- Read-only review shortlists, audit log, hard refusal of deletion execution.
- JSON/CSV/escaped static HTML reporting, TOML config, offline bounded natural-language routing and actual scan/query measurement command.
- Automated unit/integration tests; GitHub Actions matrix for Windows/Linux Python 3.11/3.12.

## Not yet implemented / not yet established

- **No real labelled Windows dataset or trained, validated deployment model.** Demo generation/training is reproducible and genuinely learns, but synthetic results do not count as research evidence.
- **No real independent annotator agreement or cross-device study results.** The tools and protocol exist; the participants/data do not yet.
- **Windows CI/native tests have not been executed in this sandbox.** A workflow is provided, not a claim that Windows already passes.
- No active-use/process/service dependency enumeration, verified owner intent, Authenticode verification, installed-application registry inventory or Windows allocated-size API. These fields are not silently assumed safe/false.
- No destructive executor, Recycle Bin integration or application-specific cleanup procedure invocation. Every cleanup is analysis-only. LOW RISK is reserved for future validated cases and is not currently emitted.
- No recursive folder deletion, automatic removal, forced overrides, natural-language shell execution or LLM API dependency.
- No perceptual media near-duplicate discovery. Related-group leakage prevention checks supplied grouping IDs; manual/provenance grouping quality remains a study responsibility.
- No trained directory-purpose classifier. Directory explanations use KB context/aggregates; file ML is not evidence of a directory's contents.
- No incremental filesystem change-journal scanner, compressed/sparse Windows allocation accounting, or atomic scan snapshot. Long-path operation depends on Python/Windows policy; it needs native validation. Read-only traversal has race limitations on concurrently modified paths; nothing destructive is performed.
- No Docker volume deletion, Docker API inspection, historical anomaly model, persistent anomaly/forecast estimator artifact, learned-to-rank objective or rank-quality study.
- No claimed hyperparameter search, XGBoost comparison, large-data out-of-core training, device-bootstrap CIs, calibrated forecasting intervals or independent chatbot-accuracy evidence.
- Metadata/reporting bounds are explicit: directory aggregation uses O(number of directories), duplicate results retain candidate groups, supervised training loads its dataset into memory, and cleanup considers a bounded largest-file shortlist.

## Database implementation

Implemented tables: `scans`, `files` (including directory metadata), `scan_errors`, `storage_history`, `model_versions`, `ml_predictions`, `risk_assessments`, `anomaly_results`, `cleanup_recommendations`, `cleanup_operations`. Scan rows carry full-volume measurements and exclusion scope. Category/model results are JSON with version references; application summaries and directory totals are derived rather than placed in empty placeholder tables. Full production schema normalization, retention controls and migrations beyond the initial additive fields remain future work.

## Validation performed in this environment

- **90 tests passed** locally on Linux; native Windows execution is still pending.
- Ruff static checks/format checks.
- CLI smoke: scan, saved analysis, queries, duplicate search, report formats, refused execution and model training/loading.
- A generated synthetic four-cohort dataset was trained, calibrated and persisted under the ignored `artifacts/` directory. Its strict default policy abstained; this is expected with insufficient validation evidence.
- Scan/query benchmark exercised against this small source tree. It is an engineering smoke check, not a Windows-drive performance result or independent chatbot evaluation.

## Next implementation/study gates

1. Run the Windows matrix and disposable Windows VM safety/ACL/junction/long-path tests.
2. Collect consented, independently annotated, grouped cohorts following the resubmission documents.
3. Train/freeze models and report real device-level safety/coverage tradeoffs and uncertainty.
4. Add audited application-specific/native validation only where justified; keep unknowns as unknown.
5. Consider any future explicit-confirmation execution stage only after separate safety review. Publication readiness depends on defensible novelty/prior-work comparison and empirical evidence, not the number of features.
