# Evaluation plan and reporting contract

**Pre-study plan; empirical results pending.** Do not fill tables with invented performance, treat synthetic files as participants, or tune controls against test results.

## 1. Questions and hypotheses

Primary: Does the full conservative pipeline reduce unsafe recommendations on independent users/devices relative to standard classifiers and simple cleanup rules, at a useful measured recommendation coverage?

Secondary: What coverage is lost to calibration/abstention/protection? How robust is it to device/application differences? Are anomaly review, priority ranking, forecast and grounded queries useful at acceptable scan/query cost?

Hypotheses are not conclusions. A fully abstaining system may have no unsafe recommendations but offers no recommendation coverage; report both, with undefined precision shown as undefined. A non-significant or negative result is a valid outcome.

## 2. Cohorts and leakage prevention

1. Recruit consenting Windows users with varied applications, storage sizes, filesystem layouts and usage patterns. Aim for multiple independent devices/users in every cohort; the four-way design needs at least four distinct user/device identities, more than a three-person team's own single devices.
2. Freeze four **user- and device-disjoint** cohorts: fitting, probability calibration, policy selection, and final test. Do not fit calibration on test data or select the threshold by the test curve.
3. Include exact-content hashes and related-family groups. Prevent exact duplicates, near-identical versions/media, generated siblings, shared dependency/template families, and repeated snapshots crossing partitions. The loader rejects cross-split user/device/hash/group IDs; auditors must verify actual grouping quality and genuine identities.
4. Resolve families spanning devices by removing copies from all but one cohort or assigning suitable devices before the freeze. Log exclusions, label distributions and potential selection bias.
5. Do not silently drop UNKNOWN files or protected examples. Include naturally occurring metadata patterns that disagree with the model (for example executable/database files named like caches) in a separate clearly identified safety-challenge set.
6. Freeze dataset/annotation versions, seed, manifests, thresholds, declared risk target and model settings. Save the dataset digest and software versions. If a cohort is changed, it is a new experiment, not the same test.
7. Folder-wise splits may be shown as an **optimistic diagnostic only**, clearly separate from the primary cross-device experiment. They do not establish generalization. A same-device/near-duplicate-permitting result cannot replace the strict run.

For stronger evidence, repeat the complete experiment with multiple held-out device/user cohorts, keeping test users independent in each run. The current training command executes one preassigned four-way split; repeated experiments and grouped uncertainty summaries must be orchestrated as a study, not claimed to be implemented cross-validation.

## 3. Frozen experimental arms

Training saves the following held-out comparisons:

| Arm | Meaning |
|---|---|
| Fixed rules | temporary/cache context, `.tmp`/`.cache`, modification age ≥30 days; abstain otherwise |
| Decision Tree | fixed-depth ordinary supervised argmax baseline |
| Random Forest | ordinary uncalibrated supervised argmax baseline |
| Full risk-aware | calibrated Random Forest + independent group-based threshold + support check + protection |
| No veto | same frozen policy/support check, protection removed **offline only** |
| No abstention | calibrated argmax + protection, no threshold/support withholding |
| No calibration (fixed policy) | raw probabilities evaluated with the already frozen threshold, support and protection |
| No controls | raw Random-Forest argmax without safety veto/policy |

The fixed-rule arm is intentionally a comparator, **not deployed advice** that old temporary files are safe. All ablations operate on dataset rows and metrics; none enable unsafe application commands. “No calibration” keeps the threshold fixed to isolate one change; it is not an optimally retuned uncalibrated selective classifier. Add a separately policy-tuned uncalibrated selective baseline for a stronger publication comparison, using only its policy cohort.

Do not tune category/priority hyperparameters on test. Current settings are fixed; if tuning is added, use grouped training-only inner folds. Record search space and compute budget. Include XGBoost only if actually trained/evaluated, not as an unimplemented name in results.

## 4. Primary safety metrics and denominators

Let `R` be files accepted by the model/policy/gate for review (called “safe” **only as a dataset decision label**), `S` the SAFE annotations, `I` IMPORTANT annotations and `U` UNKNOWN annotations.

- **Safe-class precision:** `|R ∩ S| / |R|`. Undefined when `R` is empty.
- **False-safe rate:** `|R ∩ I| / |I|` (important→safe). Undefined if no IMPORTANT examples. This is not `1 - precision`.
- **Unsafe recommendation count:** `|R ∩ (I ∪ U)|`.
- **UNKNOWN recommended count:** `|R ∩ U|`, reported separately; lack of evidence is not safe.
- **Recommendation coverage:** `|R| / N`.
- **Abstention rate:** number of unknown decisions / `N`.
- **Decision coverage:** one minus abstention; includes positive retain decisions and is not the same as recommendation coverage.
- **Protection violations:** protected examples accepted for review; the deployed full pipeline should have zero by construction for protections it can actually identify. Challenge sets must cover unknown native integrations and path alias/race cases rather than implying perfect OS knowledge.

Also report class precision/recall/F1/accuracy, confusion matrices, safe-vs-rest ROC-AUC where both classes exist, and calibrated Brier score. The training report currently includes category classification metrics, safety confusion/ROC/Brier and priority classification metrics. Add reliability diagrams/ECE and risk–coverage curves to the offline study, without retrospectively selecting policy thresholds from the test curve.

### Statistical reporting

Report per-device and pooled counts. Bootstrap by **held-out user/device**, not individual files, for primary metric confidence intervals and paired differences across systems. With very few devices, show the individual results and avoid overstating confidence. Provide accepted related-group counts and important-file denominators. The policy's approximate Wilson upper bound is for selection on policy groups, not a substitute for uncertainty on test users/devices. No formal safety guarantee follows from zero observed mistakes.

The current implementation provides point metrics and policy diagnostics, not device-bootstrap confidence intervals. Those remain part of the real-study analysis, to be added when there are enough independent devices.

## 5. Safety challenge tests

Automated fixtures cover protected paths on arbitrary drive letters, case variations, `SystemRoot`, boot components, system attributes, WRP override, installed application state, executable/database extensions, personal data, hard links, symlink loops, aliases, root-link rejection, permission failures, cancelled scans, changed files during duplicate checking, identical-size/nonidentical contents, insufficient policy data, grouped policy counts and refused execution.

Run Windows-native validation on disposable test directories/VMs. Check actual junctions, Windows ACL denial, NTFS hard links, WRP responses, long paths and configured Windows path policy. Add Authenticode/process/dependency tests only when those integrations exist. Never delete participant data for a safety challenge. Model outputs must not weaken protections even if a fake/stub model returns probability 1.0.

## 6. Other ML components

### Category and review priority

Report per-class confusion/precision/recall/F1, unknown coverage and per-device drift. For priority ranking, have independent reviewers label relevance without seeing the ranking; report precision@k, recall@k and NDCG@k plus bytes represented and time to review. Classification accuracy alone does not prove a useful ranking. No real ranking-quality results have yet been collected.

### Anomaly detection

Create a held-out labelled directory review set: naturally occurring outliers plus clearly marked controlled growth/log/cache events. Separate synthetic injections from natural observations. Reviewers decide whether each flag warrants investigation, **not deletion**. Report precision@k, recall of labelled events, false positive rate and reviewer utility. Note that nested directory observations are dependent and current Isolation Forest detects within-scan structural outliers, not a trained temporal growth distribution.

### Forecasting

Collect daily complete scans with the same root/exclusions over multiple weeks. Never manufacture history by changing timestamps or duplicate a single scan into multiple dates. Use expanding-window temporal backtests and horizons actually observed. Report MAE/RMSE, compare with persistence/last-value and simple linear-growth baselines, and check interval coverage if calibrated intervals are later implemented. Current bands use historical absolute errors only and are descriptive, not confidence guarantees. Whole-volume free-space forecasting requires actual scope-wide usage history, not extrapolated directory totals.

### Exact duplicates

Use controlled same-content/different-name files, same-size/different-content files, hard links, unreadable files, changing files, and empty files. Verify byte equality after hashing. Measure detection precision/recall and throughput on opt-in content reads. Recoverable-space estimates are conditional on retaining a correct copy, independent storage allocation and user approval; identical content alone does not authorize removal.

## 7. Latency, scalability and query evaluation

`disklens benchmark <root> --query-cases <jsonl> --repeats 3` records actual scan and query timings, status, platform, per-question intent predictions, median/p95 and raw samples. Repeated runs are warm/mixed-cache; the tool does not flush OS caches. Report at least:

- File/directory count, bytes, drive type, CPU/RAM, Windows/Python/package versions, permissions, exclusions and incomplete scans.
- Scan wall time and throughput, error count, peak process RSS, duplicate hash/byte-verification time, ML inference time, query median/p95.
- Cold-cache and warm-cache separately **only if actually controlled**, otherwise disclose cache conditions.
- Large-tree stress tests. Metadata traversal streams into SQLite, but aggregate reports use directory-count memory, duplicate reports use candidate/group memory, and training uses an in-memory dense design matrix. Do not claim constant-memory operation for the whole pipeline.

Use independent participant-authored paraphrases, not only the development examples. Measure intent accuracy, unsupported-question abstention and human-checked answer grounding against the frozen scan/KB; distinguish command guidance from factual answers. Safety questions cannot authorize actions. Current `benchmark` measures **intent accuracy**, not arbitrary free-form chatbot factual accuracy, because no generative chatbot is implemented. Publish query set provenance and per-intent failure counts. Bundled questions are smoke tests, not research evidence.

## 8. Required final report

Fill only after conducting the study:

| System | Test users/devices | Important count | Accepted count | Safe precision | False-safe rate | Unknown accepted | Recommendation coverage | Abstention | Device-level CI |
|---|---|---|---|---|---|---|---|---|---|
| Rules | pending | pending | pending | pending | pending | pending | pending | pending | pending |
| Ordinary classifier | pending | pending | pending | pending | pending | pending | pending | pending | pending |
| Risk-aware pipeline | pending | pending | pending | pending | pending | pending | pending | pending | pending |

Also attach annotation agreement/adjudication, cohort/leakage audit, baselines/ablation settings, latency table, anomaly review, priority ranking, forecast backtests and limitations. No automatic deletion occurs, so **actual recovered storage is not measured and must not be reported**. Report candidate bytes only as conditional opportunity estimates.

## 9. Acceptance gates

1. Unit/integration tests and a reviewed Windows validation run pass.
2. Real independent annotation report and cohort/leakage audit are complete.
3. Useful recommendation coverage and lower unsafe recommendations are demonstrated with defensible comparisons, or explicitly reported as not demonstrated.
4. No unsupported safety/novelty/publication-readiness claims.
5. A future destructive executor requires a separate reviewed threat model and application-specific validation. Explicit confirmation is necessary but cannot compensate for incomplete safety evidence.
