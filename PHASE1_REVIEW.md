# Phase 1 Review — Data Correctness (P1, P2, P7)

**Project:** Adversary Infrastructure Tracking & Clustering  
**Scope:** S001–S004; passive collection only. Candidate relationships remain candidates. Cluster membership is not actor attribution. Heuristic scores are not probabilities.

## Summary

Phase 1 changes are included in this project copy. Extraction is field-aware, node lifecycle and shared-infrastructure flags are used by downstream scoring/qualification, excluded alerts are blocked at the dashboard and backend, and exact known test records can be archived and reversibly restored.

The original raw evidence files were not modified. A separate verification copy of the SQLite database was used for the Phase 1 rerun and cleanup.

## Changes

### P1 — Extraction and lifecycle

- Replaced broad arbitrary-string scanning with named-field extraction for supported DNS/IP/certificate/hash data.
- Added hostname syntax and public-suffix validation; pseudo-TLDs and common file extensions are rejected as domain indicators.
- Added public/global IP validation. Private, reserved, and non-global addresses are not emitted as host indicators.
- Added `config/shared_infrastructure.json`, a versioned offline Cloudflare range list with provider, source, reason, and list-entry date. Shared nodes remain represented but are flagged and excluded from actionable scoring/qualification.
- Added node lifecycle metadata and provenance fields; stale extraction artifacts are retired with reasons rather than deleted. Candidate edges and alerts derived from retired/unsupported nodes are also retired. Repeated extraction/qualification is idempotent.
- Updated candidate-edge and clustering inputs to ignore retired/shared infrastructure while preserving candidate-edge semantics.

### P2 — Alert qualification

- Qualification reads node lifecycle and validation flags and runs as a pipeline stage.
- Shared, retired, invalid, and otherwise excluded observables are not actionable.
- Dashboard controls disable triage for excluded alerts, and the backend rejects such triage attempts independently of the UI.
- Valid active nodes can be re-qualified on subsequent runs; previously retired alert state is not left stale when the underlying node is valid again.

### P7 — Production test-record cleanup

- Added `scripts/cleanup_test_records.py` to archive only the exact known test reasons from triage history and edge-review JSON.
- Cleanup creates a SQLite backup and a JSON archive before modifying the working records. It is idempotent.
- Restore validates archive checksums and refuses to overwrite a review file that changed after cleanup.
- Tests use temporary files/databases. The cleanup was run only on the isolated verification copy, not on the uploaded original archive.

## Files changed or added

- `config/shared_infrastructure.json` (added/updated)
- `config/public_suffix_list.dat` (bundled offline snapshot retained)
- `scripts/entity_validation.py` (new)
- `scripts/extract_entities.py`
- `scripts/build_candidate_edges.py`
- `scripts/cluster_infrastructure.py`
- `scripts/generate_alerts.py`
- `scripts/qualify_alerts.py`
- `scripts/cleanup_test_records.py` (new)
- `dashboard/alerts.py`
- `dashboard/app.py`
- `tests/test_extract_entities.py`
- `tests/test_alert_qualification.py`
- `tests/test_candidate_edges.py`
- `tests/test_dashboard_alerts.py`
- `tests/test_cleanup_test_records.py` (new)

## Verification performed

Verification was performed on a separate working copy of the project and an isolated database copy.

| Check | Result |
|---|---:|
| Nodes after Phase 1 | 47 |
| Retired nodes | 12 |
| Edges after Phase 1 | 50 |
| Retired edges | 17 |
| Alert records | 43 |
| Eligible, active alerts | 28 |
| Excluded alerts | 15 |
| Known test phrases remaining in triage history | 0 |
| Known test phrases remaining in edge-review JSON | 0 |
| Raw evidence files | 14 |
| Raw evidence hashes changed | 0 |
| Non-STIX pytest suite | 82 passed |

Specific listed metadata/file-name/netblock artifacts were retired; the listed Cloudflare IPs remain flagged as shared. All the named problematic/shared values had zero eligible-and-active alerts in the verification copy.

The P1 downstream scripts (extraction, candidate-edge build, clustering, alert generation, qualification, and cleanup) were run against the isolated copy. The complete `run_pipeline.py` end-to-end command was **not** verified successfully in this environment.

## Commands (Windows PowerShell)

Run from the unpacked project root, after installing the pinned requirements in the project's virtual environment:

```powershell
python -m pip install -r requirements.txt
python -m pytest -q
```

The Phase 1 focused tests can be run with:

```powershell
python -m pytest -q tests/test_extract_entities.py tests/test_alert_qualification.py tests/test_candidate_edges.py tests/test_dashboard_alerts.py tests/test_cleanup_test_records.py
```

To run the cleanup manually, first make a backup and then run:

```powershell
python scripts/cleanup_test_records.py
```

To restore from a specific archive (use the matching archive created by cleanup):

```powershell
python scripts/cleanup_test_records.py --restore "data/archive/test_record_cleanup/cleanup_YYYYMMDDTHHMMSSZ.json"
```

The complete pipeline currently runs the full pytest suite before pipeline scripts. Do not interpret the focused test command as a successful full-pipeline run.

## Status

| Item | Status | Notes |
|---|---|---|
| P1 field-aware extraction and lifecycle | Done | Verified on a database copy; retired nodes/edges are retained with reasons. |
| P1 bundled Public Suffix List | Partial | The included official-ancestry snapshot is IO::Socket::SSL::PublicSuffix.pm v2.089 (2024-08-29); it is versioned and offline-deterministic but is not a current 2026 PSL refresh. |
| P1 shared infrastructure list | Done | Versioned offline Cloudflare ranges with source and rationale. |
| P2 qualification and triage prevention | Done | Qualification and backend/UI guards verified. |
| P7 reversible test-record cleanup | Done | Isolated-copy cleanup, backup, restore guards, and exact-phrase test added. |
| Phase 1 non-STIX test coverage | Done | 82 tests passed. |
| Full pytest suite / end-to-end pipeline | Blocked / Unverified | Two STIX test modules could not be collected because `stix2` is missing in the execution environment; the package index was unavailable. |

## Self-review and remaining limitations

1. The bundled Public Suffix List remains an older official-ancestry snapshot. Refresh it from the official PSL source when network access is available, then rerun domain validation tests.
2. The full pytest suite, including STIX tests, and the complete pipeline command remain unverified here because the pinned `stix2` dependency could not be installed in this environment. The 82-test result excludes those two STIX test modules.
3. This phase intentionally does not redesign alert semantics (P3), scoring (P4), typed pivots/clustering (P5), temporal semantics (P6), analyst-review storage (P8), portability (P10), or the broader dashboard refactor and visual upgrade (P9 and final visual phase).
