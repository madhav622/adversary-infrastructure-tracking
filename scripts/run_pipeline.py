from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
LOG = ROOT / "logs" / "pipeline.log"

STEPS = [
    ("STIX database loading", "scripts/load_stix_db.py"),
    ("Infrastructure graph", "scripts/build_graph.py"),
    ("Raw evidence ingestion", "scripts/import_raw_evidence.py"),
    ("Entity extraction", "scripts/extract_entities.py"),
    ("Candidate relationships", "scripts/build_candidate_edges.py"),
    ("Infrastructure clustering", "scripts/cluster_infrastructure.py"),
    ("Alert generation", "scripts/generate_alerts.py"),
    ("Alert qualification", "scripts/qualify_alerts.py"),
    ("Alert exports", "scripts/export_alerts.py"),
    ("Final analyst report", "scripts/generate_final_analyst_report.py"),
    ("Analysis reports", "scripts/generate_analysis_report.py"),
    ("SIEM feed export", "scripts/export_siem_feed.py"),
]


def run_pipeline(root=ROOT, python=None, runner=None):
    root = Path(root)
    python = Path(python) if python else root / ".venv" / "Scripts" / "python.exe"
    if runner is None:
        runner = subprocess.run

    if not python.is_file():
        raise FileNotFoundError(f"Python environment missing: {python}")

    bundle = root / "exports" / "seeds_s001_s004_stix21.json"
    if not bundle.is_file():
        raise FileNotFoundError(f"STIX bundle missing: {bundle}")

    missing = [
        str(root / script)
        for _, script in STEPS
        if not (root / script).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            "Required pipeline scripts missing: " + ", ".join(missing)
        )

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    commands = [
        ("Automated tests", [str(python), "-m", "pytest", "-q"])
    ]
    commands.extend(
        (name, [str(python), str(root / script)])
        for name, script in STEPS
    )

    for index, (name, command) in enumerate(commands, start=1):
        print(f"\n[{index}/{len(commands)}] {name}", flush=True)
        result = runner(
            command,
            cwd=str(root),
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Pipeline stopped at {name} (exit code {result.returncode})"
            )
        print(f"Completed: {name}", flush=True)

    return len(commands)


def main():
    logging.basicConfig(
        filename=str(LOG),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    try:
        count = run_pipeline()
        logging.info("Pipeline completed successfully: %d stages", count)
        print(f"\nPIPELINE SUCCESS: {count} stages completed.")
        return 0
    except Exception as exc:
        logging.exception("Pipeline failed")
        print(f"\nPIPELINE ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
