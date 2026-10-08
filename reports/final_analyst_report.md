# Adversary Infrastructure Tracking and Clustering

## Final Analyst Report

Generated (UTC): 2026-10-01T11:08:16Z

Scope: S001, S002, S003, S004

## 1. Executive summary

| Metric | Value |
|---|---:|
| STIX objects | 5 |
| Infrastructure nodes | 47 |
| Seed anchors | 4 |
| Evidence records | 12 |
| Entity observations | 118 |
| Infrastructure edges | 50 |
| Alert records | 43 |
| Candidate clusters | 0 |

## 2. Seed inventory

| Seed | Endpoint | Source | First seen (UTC) | Evidence | Observations |
|---|---|---|---|---:|---:|
| S001 | 1.14.73.118:34091 | ThreatFox | 2026-09-05T11:35:01Z | 3 | 13 |
| S002 | 101.42.108.164:31337 | ThreatFox | 2026-09-27T00:00:00Z | 4 | 10 |
| S003 | 103.250.172.230:31337 | ThreatFox | 2026-09-02T00:00:00Z | 4 | 91 |
| S004 | 103.253.42.61:31337 | ThreatFox | 2026-09-14T00:00:00Z | 1 | 4 |

## 3. Infrastructure node types

| Node type | Count |
|---|---:|
| certificate-fingerprint | 10 |
| domain-name | 9 |
| file-hash-sha256 | 1 |
| ipv4-addr | 23 |
| network-endpoint | 4 |

## 4. Relationship status

| Status | Count |
|---|---:|
| candidate | 50 |

## 5. Clustering

- Algorithm: `shared-observable-pairwise-v1`
- Run ID: `cluster-run--10ecb9aca51ad06399350800406763fb9cd59e182e518344dabf5ca83d76e1ac`
- Status: completed
- Candidate clusters: 0

| Pair | Score | Result | Shared observables |
|---|---:|---|---:|
| S001 + S002 | 0.0000 | below_threshold | 0 |
| S001 + S003 | 0.0000 | below_threshold | 0 |
| S001 + S004 | 0.0000 | below_threshold | 0 |
| S002 + S003 | 0.0000 | below_threshold | 0 |
| S002 + S004 | 0.0000 | below_threshold | 0 |
| S003 + S004 | 0.0000 | below_threshold | 0 |

## 6. Alert summary

| Dimension | Value |
|---|---:|
| Total alerts | 43 |
| Status: new | 42 |
| Status: triaged | 1 |
| Severity: informational | 43 |
| Eligibility: eligible | 28 |
| Eligibility: excluded | 15 |

## 7. Alert register

| Seed | Observable | Type | Severity | Status | Eligibility | First observed | Evidence count |
|---|---|---|---|---|---|---|---:|
| S001 | 1.12.0.0 | ipv4-addr | informational | new | excluded | 2026-09-30T08:15:25Z | 1 |
| S001 | trojan.sliver | domain-name | informational | new | excluded | 2026-09-30T08:20:13Z | 1 |
| S001 | 9f79d28e3aa06aa5a68614a0855e2a782029801fc9215faa3308d844ab1d61d3 | file-hash-sha256 | informational | new | eligible | 2026-09-30T08:20:13Z | 2 |
| S001 | 162.159.36.2 | ipv4-addr | informational | new | excluded | 2026-09-30T08:24:01Z | 1 |
| S001 | 1.15.255.255 | ipv4-addr | informational | new | excluded | 2026-09-30T08:15:25Z | 1 |
| S002 | 101.43.255.255 | ipv4-addr | informational | triaged | excluded | 2026-09-30T08:38:10Z | 2 |
| S002 | 101.42.0.0 | ipv4-addr | informational | new | excluded | 2026-09-30T08:38:10Z | 2 |
| S003 | 104.21.9.123 | ipv4-addr | informational | new | excluded | 2026-09-30T09:33:06Z | 1 |
| S003 | 41cf6ff51b64be25b8e01b0878840990352e9968 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 900344d6d8a7e8de7f52c16c516e2322b33251f3 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 43.228.206.11 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 38.76.188.122 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 192.238.204.29 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 156.245.248.152 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 76681564cdd83bad65263f389cb5d657ec8d4f6b | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:21:17Z | 2 |
| S003 | 118.193.40.16 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 38.76.172.60 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | x.luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | f636db17b6bf640b38bcd64c832e6e6c9405ccef | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:21:17Z | 2 |
| S003 | 2194e61797945a3650ae0ee13f7ba433b0da3330 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 207.56.229.121 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 0e900e8ad7cd39279d9c782fe5279c443033982a | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 94ac9654637c37b672d360a8ba73e4e3c23f5214 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 18709c4151f667fe9422ee2cc7c64a5899743c52 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 103.250.172.0 | ipv4-addr | informational | new | excluded | 2026-09-30T09:21:59Z | 1 |
| S003 | 103.250.175.255 | ipv4-addr | informational | new | excluded | 2026-09-30T09:21:59Z | 1 |
| S003 | 103.250.173.255 | ipv4-addr | informational | new | excluded | 2026-09-30T09:21:59Z | 1 |
| S003 | 172.81.101.229 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | aaa570bb273a37c2f877938139331e158f1de9cf | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | www.luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 987bd1a8a78e437766a42f3d32c546dac4edcc30 | certificate-fingerprint | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | ut1-phishing.txt | domain-name | informational | new | excluded | 2026-09-30T09:24:08Z | 1 |
| S003 | btc.luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 38.76.189.178 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 103.250.172.255 | ipv4-addr | informational | new | excluded | 2026-09-30T09:21:59Z | 1 |
| S003 | *.luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:21:17Z | 1 |
| S003 | 45.207.222.65 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | sql.luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | 172.67.189.66 | ipv4-addr | informational | new | excluded | 2026-09-30T09:33:06Z | 1 |
| S003 | 103.24.216.93 | ipv4-addr | informational | new | eligible | 2026-09-30T09:33:06Z | 1 |
| S003 | luode.vip | domain-name | informational | new | eligible | 2026-09-30T09:21:17Z | 3 |
| S004 | 103.253.40.0 | ipv4-addr | informational | new | excluded | — | 1 |
| S004 | alphamountain.ai | domain-name | informational | new | excluded | — | 1 |

## 8. Analyst triage history

No analyst triage history is recorded.

## 9. Limitations

- Alert presence indicates imported passive evidence, not globally new infrastructure.
- Heuristic cluster scores are not probabilities.
- No common-actor attribution is inferred.
- Lead time is unknown without a verified outcome timestamp.
- Blocked is a manual triage status, not an automated blocking action.
- Source reliability grades are not configured.
