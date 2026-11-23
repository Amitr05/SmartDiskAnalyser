# Revised methodology — faculty resubmission

**Project:** AI-Assisted Disk Analyzer: Learning-Based Safe-to-Delete File Classification with Natural-Language Storage Queries (DiskLens)
**Team:** Amit Ravi Mishra, Abhishek, Naren
**Status:** implemented experimental framework; empirical validation pending. No publication-readiness claim.

## 1. Preserve the product, narrow the research claim

The product remains an offline Windows-first intelligent filesystem assistant: scan, explore, explain, classify, detect duplicates/anomalies, prioritize review and forecast storage. CLI is the interface; learned storage intelligence plus independent deterministic protection is the core. Natural-language routing is an optional access layer, not the research contribution.

**Research question:** On previously unseen users/devices, does calibrated selective classification combined with non-overridable protection reduce unsafe review recommendations compared with fixed rules and ordinary classifiers, at a useful measured recommendation coverage?

**Candidate contribution:** an auditable, reproducible, risk-aware file-review pipeline and cross-device benchmark/annotation protocol. Random Forest, sigmoid calibration, abstention, Isolation Forest and Linear Regression are established methods. Their integration is not automatically algorithmic novelty. A prior-work comparison and measured benefit are required before claiming a distinctive research contribution. No claim that metadata proves dispensability or that zero observed errors guarantees safety.

### Faculty revision traceability

| Required revision | Implemented mechanism | Evidence still required |
|---|---|---|
| Risk-aware novelty | Separate calibrated safety model, unknown/abstain, frozen group-aware policy, unsupported-context rejection | Risk/coverage advantage on independent real devices; related-work comparison |
| Objective labels | Operational protocol, two independent annotators, agreement/kappa tool, evidence trail, independent adjudicator, unresolved→unknown | Actual independent annotations, agreement and adjudication report |
| Protection and consent | Deterministic veto, live WRP/identity checks for review, protected paths/attributes, read-only default, execution refused/audited | Windows native validation and complete dependency checks before even considering a deletion feature |
| Generalization/leakage | Four disjoint user/device partitions; SHA-256 and related-group split validation | Independent Windows cohort and verified related-file grouping |
| Strong experiments | Safety metrics, baselines, offline ablations, latency benchmark, forecast backtesting | Real-study results, human anomaly/query assessment, confidence intervals |

## 2. Inputs and evidence boundaries

The scanner records file metadata, never file contents in SQLite. An ordinary scan does not hash files. Explicit duplicate searches and opt-in dataset content hashing read contents; deep inspection reads at most 32 header bytes. Links/reparse points are not traversed; failures and exclusions are visible. Physical allocation is separate from logical bytes, and may be unavailable. Scans are observations of a changing filesystem, not atomic snapshots.

Inference output separates:

1. **Facts:** observed metadata, measured sizes, hashes/byte comparisons, available WRP results.
2. **Curated context:** known directory purposes, not a guarantee about every child.
3. **Rules:** deterministic risk level, independent of model probabilities.
4. **Predictions:** learned category, priority and calibrated safety-label probability, identified by model version.
5. **Unknowns:** absent signatures/dependencies, unseen feature contexts, rejected thresholds, unsupported questions/history.

Raw filenames, raw paths, content hashes, group IDs, user IDs, device IDs and labels are **not predictive features**. Location is mapped to a broad context: system, application, personal, cache, temporary, development or unknown. Paths remain private operational data, not a feature vocabulary that memorizes a machine.

## 3. Training data contract

Each JSONL record has:

| Field | Meaning |
|---|---|
| `record_id` | unique pseudonymous observation ID |
| `device_id`, `user_id` | stable pseudonyms for splitting, never model inputs |
| `split` | train / calibration / policy / test |
| `sha256` | full lowercase content hash, for leakage checks only |
| `related_group` | shared ID for duplicate/near-identical/project/snapshot families |
| `path`, `extension`, `size`, `modified_days`, `depth` | private metadata; broad location derived from path |
| `is_hidden`, `is_system`, `is_readonly`, `is_link`, `nlink` | available metadata/attributes; defaults documented in features |
| `label` | safe / important / unknown, under annotation protocol |
| `category` | independently labelled file purpose |
| `priority` | high / medium / low / retain / unknown review priority |
| `evidence` | nonempty provenance and contextual justification |
| `annotation_resolution` | optional tool-produced provenance of agreement/adjudication |
| `synthetic` | true for generated wiring examples; never remove to disguise synthetic origin |

Exported records deliberately have blank grouping/evidence and may lack content hashes: they are **not train-ready labels**. Valid hashes, nonnegative finite numeric features, label membership, unique IDs and non-overlapping user/device/hash/group partitions are checked. The software cannot verify that an annotator's evidence is truthful, a physical device ID is genuine, or all near-duplicate families were found; those require a dataset audit.

The present supervised pipeline is **file-only**. Directories are represented through aggregates, curated explanations and learned directory outliers, not through a file classifier misapplied to directory entries. Annotation labels are not inferred from directory membership.

### Feature engineering

`DictVectorizer` one-hot encodes extension and broad location. Numeric inputs: `log1p(size)`, days since modification (capped at 36,500), depth and hidden/system/read-only/link indicators. Negative ages caused by clock skew are bounded to zero at inference. Missing depth/flags default to zero/false; the `unknown` location/empty extension have explicit values. Signature, ownership, access and process-use evidence are not invented; currently absent native integrations are disclosed. Access timestamps are excluded because they can be disabled, stale or changed by scanning itself.

A dense encoded matrix is used for the initial small academic dataset. Large-dataset/out-of-core training is not implemented. Save manifests/dataset digests and inspect extension/location distributions, label balance, duplicate-group sizes and missing metadata before training. Full EDA and hyperparameter search are future study steps; current model hyperparameters are fixed and reproducible, not falsely described as tuned.

## 4. Supervised components

### Category

A balanced Random Forest (120 trees, max depth 14, minimum leaf size 3, seed 42) learns purpose labels. Output is unknown when the maximum category probability is below 0.8 or the feature context is unsupported. This 0.8 category-display cutoff is fixed, not a calibrated safety claim. Global impurity feature importances are exported for debugging; they are not per-file causal explanations.

### Review priority

A separate Random Forest learns review-priority labels, not category-derived pseudo-labels or deletion actions. Only eligible file-review items can reach the shortlist. Sorting prioritizes policy-approved review candidates, learned priority, then size. The default shortlist considers the largest 200 files and reports that bound; it is not an exhaustive drive-wide cleanup ranking. No claim of learning-to-rank/NDCG optimization is made.

### Safety research classifier

A third balanced Random Forest learns safe/important/unknown. Fit on training devices only. Sigmoid `CalibratedClassifierCV` wraps a frozen fitted estimator and is fit on the independent calibration cohort. Class probabilities concern the operational annotations, not a verified physical probability of harm.

## 5. Selective risk policy

Let `p_s(x)` be the calibrated safe-label probability. Let `G(x)` be the independent review-eligibility gate. Let `S(x)` be the limited support check: extension and broad location observed during fitting, and size no more than 10× the largest training size on the log scale. This check is a simple guard, **not a complete out-of-distribution detector**.

A file is a model-approved **review candidate** only if:

```
G(x) AND S(x) AND threshold exists AND p_s(x) >= threshold
```

Otherwise a predicted important file is retained; other cases abstain/unknown. At live inference the system rechecks the independent safety gate. Synthetic models always withhold live review approval.

The policy cohort is independent of both fitting and calibration. Thresholds are the fixed grid:

```
0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.975, 0.99, 0.995, 0.999, 1.0
```

For each threshold:

1. Apply gate/support checks before collecting accepted files.
2. Collapse accepted files by their related-file group.
3. A group fails if **any** accepted member is labelled important **or unknown**.
4. Calculate a one-sided approximate Wilson upper bound for the group failure fraction, using alpha `0.05 / 11` (fixed-grid Bonferroni adjustment).
5. Require at least 100 accepted groups (configurable) and upper bound ≤ 0.01 (default target).
6. Freeze the lowest passing threshold (maximum recommendation coverage on this fixed nested grid).
7. If none pass, save `threshold: null`; abstain from all safe recommendations.

This is **empirical, approximate control**, not a formal distribution-free guarantee. Wilson coverage is approximate, grouping may be incomplete, groups within a device may still be correlated, and user/device shift breaks exchangeability. Device-level uncertainty analysis and realistic deployment testing remain necessary. The 1% target concerns the validation group failure fraction, **not** the important→safe test metric, not individual future harm, and not an assurance that 1% risk is acceptable to any user. Do not tune it after looking at test results.

### Difference from baselines

- Fixed rules map suffix/location/age directly to an outcome and do not learn probabilities.
- A conventional classifier always selects an argmax class, with no separate calibration/policy cohort and no explicit uncertainty withholding.
- DiskLens separates learning, calibration, validation-policy selection and test; can decline all recommendations; and cannot overrule deterministic protection.
- The actual incremental benefit must be demonstrated through baselines and ablations, rather than presumed from this architecture.

## 6. Protection independent of ML

Risk levels: CRITICAL, HIGH RISK, CAUTION, LOW RISK, USER REVIEW. Current rules never assign LOW RISK because the required contextual validation is not yet implemented. An old `.tmp` receives CAUTION, not a promise of safety.

Protection includes case-insensitive path-component rules on any drive, custom `SystemRoot`/`windir`, boot/pagefile names, system attributes, WRP when available, reparse/alias/link checks, application/configuration locations, executable/database/sensitive extensions and personal-data review. Unknown metadata does not establish absence of dependencies. More dangerous findings take precedence. Live shortlists refresh identity/size/timestamps and skip changed/missing entries.

Windows Authenticode verification, service/process dependencies, owner permissions, installed-application registry mapping and application-specific safe cleanup validation are not implemented. Therefore no model/rule combination currently grants deletion authorization. `cleanup --execute` fails closed. No arbitrary recursive deletion or shell-execution path exists. A future execution stage must require exact-file validation, explicit per-operation consent, dry-run, identity revalidation, supported OS/application mechanisms and audit logging; it must never accept a natural-language deletion request as consent.

## 7. Other intelligence components

- **Duplicates:** group by size, hash only same-size nonempty candidates, check scan identity, then verify bytes. Hard links are not reclaimable duplicate copies. Equality proves content equality only, not dispensability.
- **Anomalies:** per-scan Isolation Forest on directory size/count/max/mean/depth (minimum 16 non-root observations). It detects relative structural outliers, not persistent-data safety; temporal growth is separately visible in scan comparisons. Historical anomaly learning remains future work.
- **Forecast:** same-root/same-exclusion complete scans, last observation per UTC date, ≥5 dates spanning ≥7 days. Linear Regression with expanding-window temporal errors, MAE/RMSE and descriptive 95th-percentile absolute-error bands. These are not calibrated future intervals. Directory growth is not whole-volume free space; supplied capacity must match scope.
- **Queries:** deterministic offline routing to grounded functions. No retrieved claim may override scanner/safety results; unsupported intents abstain. The model-based contribution remains the actual file/safety/priority training and anomaly/forecast fitting, not the query router.

## 8. Reproducibility and release gate

Use a fixed seed, frozen study manifest, disjoint identities/content families, immutable artifact directories, dataset hash and recorded scikit-learn version. Joblib artifacts must be trusted and version-matched. No raw user files or private exports enter Git. CI checks scanner, safety, duplicates, policy, persistence, analysis and CLI. Real Windows validation and an independent-device results report are required before advancing beyond research-prototype status.
