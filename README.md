# Adversary Infrastructure Tracking & Clustering

A cybersecurity research project for tracking and clustering adversary infrastructure using passive Cyber Threat Intelligence (CTI), infrastructure pivots, evidence correlation, graph analysis, and risk-based scoring.

## Project Overview

The project takes known seed Indicators of Compromise (IOCs) and performs passive infrastructure pivots to identify related observables such as IP addresses, domains, TLS certificates, hashes, and other infrastructure indicators.

Collected evidence is normalized, correlated, represented as infrastructure relationships, and analyzed to support analyst-driven investigation.

The current project scope focuses on seed cases **S001–S004**.

## Objectives

- Track adversary-related infrastructure from known seed IOCs.
- Perform passive infrastructure pivoting using collected CTI evidence.
- Normalize heterogeneous evidence into a consistent structure.
- Build candidate relationships between infrastructure entities.
- Apply evidence-based scoring to infrastructure relationships.
- Generate analyst-focused alerts and reports.
- Provide a dashboard for investigation and review.
- Preserve analyst review decisions and triage history.

## Core Pipeline

Seed IOCs → Raw CTI Evidence → Entity Extraction → Normalization → Candidate Relationships → Infrastructure Graph → Clustering & Scoring → Alerts → Analyst Review → Reports / SIEM Feed

## Key Components

### CTI Evidence Processing
Processes collected evidence from multiple CTI sources and extracts infrastructure-related observables.

### Infrastructure Pivoting
Supports passive pivots across infrastructure indicators such as:

- IP addresses
- Domains
- TLS certificates
- File hashes
- Related infrastructure observations

### Graph Analysis
Infrastructure entities and their relationships are represented as a graph. Candidate relationships can be reviewed before being used for analysis.

### Evidence-Based Scoring
Infrastructure relationships are evaluated using observable-based evidence rather than assuming that shared infrastructure automatically means common ownership or attribution.

### Alerting
The system generates analyst-facing alerts for relevant infrastructure observations and maintains alert qualification and triage information.

### Analyst Dashboard
A Streamlit-based dashboard provides views for infrastructure investigation, alerts, pivot analysis, source quality, and review decisions.

## Technology Stack

- Python
- Streamlit
- SQLite
- STIX 2.1
- Pandas
- Network / graph analysis
- Cyber Threat Intelligence (CTI)
- JSON / CSV
- Pytest

## Project Structure

```text
adversary-infrastructure-tracking/
├── config/          # Project configuration
├── dashboard/       # Streamlit dashboard
├── data/
│   ├── raw/         # Collected CTI evidence
│   ├── review/      # Analyst review decisions
│   └── seeds/       # Seed IOC definitions
├── exports/         # Generated feeds and analysis outputs
├── reports/         # Analyst reports
├── scripts/         # Pipeline and analysis scripts
├── tests/            # Automated tests
├── requirements.txt
└── README.md
