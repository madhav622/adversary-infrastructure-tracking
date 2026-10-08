# Adversary Infrastructure Tracking and Clustering

## Analysis Report

Generated (UTC): 2026-10-01T11:08:16Z

### Scope

Seed IDs: S001, S002, S003, S004

S005 is excluded from this analysis.

### Project statistics

| Metric | Count |
|---|---:|
| STIX objects | 5 |
| Infrastructure nodes | 47 |
| Seed anchors | 4 |
| Evidence records | 12 |
| Entity observations | 118 |
| Infrastructure edges | 50 |
| Cluster runs | 1 |
| Clusters | 0 |
| Cluster memberships | 0 |

### Seed overview

| Seed | Endpoint | First seen (UTC) | Last seen (UTC) | Evidence files | Observations | Source |
|---|---|---|---|---:|---:|---|
| S001 | 1.14.73.118:34091 | 2026-09-05T11:35:01Z | — | 3 | 13 | ThreatFox |
| S002 | 101.42.108.164:31337 | 2026-09-27T00:00:00Z | — | 4 | 10 | ThreatFox |
| S003 | 103.250.172.230:31337 | 2026-09-02T00:00:00Z | — | 4 | 91 | ThreatFox |
| S004 | 103.253.42.61:31337 | 2026-09-14T00:00:00Z | — | 1 | 4 | ThreatFox |

### Infrastructure node types

| Type | Count |
|---|---:|
| certificate-fingerprint | 10 |
| domain-name | 9 |
| file-hash-sha256 | 1 |
| ipv4-addr | 23 |
| network-endpoint | 4 |

### Relationship status

| Status | Count |
|---|---:|
| candidate | 50 |

### Clustering results

- Algorithm: `shared-observable-pairwise-v1`
- Run ID: `cluster-run--10ecb9aca51ad06399350800406763fb9cd59e182e518344dabf5ca83d76e1ac`
- Status: completed
- Threshold: 0.5
- Candidate clusters: 0

| Seed pair | Score | Status | Shared observables |
|---|---:|---|---:|
| S001 + S002 | 0.0000 | below_threshold | 0 |
| S001 + S003 | 0.0000 | below_threshold | 0 |
| S001 + S004 | 0.0000 | below_threshold | 0 |
| S002 + S003 | 0.0000 | below_threshold | 0 |
| S002 + S004 | 0.0000 | below_threshold | 0 |
| S003 + S004 | 0.0000 | below_threshold | 0 |

No pair met the configured candidate threshold under the current evidence and scoring rules.
This does not establish that the seed infrastructures are unrelated.

### Methodology and limitations

- Scores are rule-based heuristic values, not probabilities.
- Shared IP addresses are excluded from the current pair score.
- A candidate relationship is not proof of direct connectivity or common control.
- CDN usage, shared hosting, infrastructure reuse, and temporal changes may affect apparent overlap.
- No threat-actor attribution is inferred.
- The report reflects the currently imported evidence only.
- Some source first-seen timestamps were blank; available listing dates from the seed notes were used as fallbacks.

### Provenance

Raw evidence records, their source names, paths, and SHA-256 hashes are retained in the local SQLite database.
