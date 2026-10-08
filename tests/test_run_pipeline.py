import sys
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_pipeline import run_pipeline, STEPS


def prepare(tmp_path):
    python = tmp_path / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")

    bundle = tmp_path / "exports" / "seeds_s001_s004_stix21.json"
    bundle.parent.mkdir(parents=True)
    bundle.write_text("{}", encoding="utf-8")

    for _, relative in STEPS:
        script = tmp_path / relative
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("# test placeholder\n", encoding="utf-8")

    return python


def test_pipeline_executes_all_steps(tmp_path):
    python = prepare(tmp_path)
    calls = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    count = run_pipeline(tmp_path, python, fake_runner)

    assert count == len(STEPS) + 1
    assert len(calls) == len(STEPS) + 1
    assert calls[0][1:3] == ["-m", "pytest"]


def test_pipeline_stops_on_failure(tmp_path):
    python = prepare(tmp_path)
    calls = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1 if len(calls) == 3 else 0)

    with pytest.raises(RuntimeError, match="exit code 1"):
        run_pipeline(tmp_path, python, fake_runner)

    assert len(calls) == 3


def test_missing_script_prevents_execution(tmp_path):
    python = prepare(tmp_path)
    (tmp_path / STEPS[-1][1]).unlink()
    calls = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    with pytest.raises(FileNotFoundError, match="scripts missing"):
        run_pipeline(tmp_path, python, fake_runner)

    assert calls == []
