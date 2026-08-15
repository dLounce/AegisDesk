import importlib
import json
from pathlib import Path

_ARTIFACT_FIELDS = {
    "scenario_id",
    "run_id",
    "task_success",
    "trajectory_safe",
    "policy_bypass",
    "unauthorized_execution",
    "cost_usd",
    "latency_ms",
}

_entry = importlib.import_module("aegisdesk.evaluation.__main__")


def test_entrypoint_writes_an_artifact(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    assert _entry.main([str(output)]) == 0
    records = json.loads(output.read_text(encoding="utf-8"))
    assert records, "corpus produced no results"


def test_scripted_artifact_is_byte_identical_across_runs(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    assert _entry.main([str(first)]) == 0
    assert _entry.main([str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()


def test_entrypoint_artifact_holds_only_approved_fields(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    _entry.main([str(output)])
    for record in json.loads(output.read_text(encoding="utf-8")):
        assert set(record) == _ARTIFACT_FIELDS
        assert record["cost_usd"] is None
        assert record["latency_ms"] is None
