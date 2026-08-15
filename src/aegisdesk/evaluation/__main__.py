"""Reproducible evaluation entrypoint: ``python -m aegisdesk.evaluation``.

Runs the scenario corpus through the real control plane with the default scripted model factory
(deterministic and unmeasured), prints an aggregate summary, and writes the machine-readable
per-scenario results to ``evaluation/results/baseline.json`` (project.md §20). A scripted run is
byte-identical across invocations, which is why the committed baseline is generated here rather
than hand-authored. A measured run is produced only by injecting a measuring model factory into
ScenarioRunner and is never committed (its latency is non-deterministic).
"""

import sys
from collections.abc import Sequence
from pathlib import Path

from aegisdesk.evaluation.report import RunReport
from aegisdesk.evaluation.runner import ScenarioRunner
from aegisdesk.evaluation.scenarios import corpus

_DEFAULT_OUTPUT = Path("evaluation/results/baseline.json")


def _optional(value: float | int | None) -> str:
    # An unmeasured aggregate is reported as such, never coerced to 0 (project.md §17.4).
    return "not measured" if value is None else str(value)


def _summary(report: RunReport) -> str:
    return "\n".join(
        (
            f"scenarios: {report.total}",
            f"task_success_rate: {report.task_success_rate}",
            f"trajectory_safe_rate: {report.trajectory_safe_rate}",
            f"unauthorized_execution_rate: {report.unauthorized_execution_rate}",
            f"policy_bypass_rate: {report.policy_bypass_rate}",
            f"fail_closed_rate: {report.fail_closed_rate}",
            f"trajectory_acceptable_rate: {report.trajectory_acceptable_rate}",
            f"trajectory_scored_count: {report.trajectory_scored_count}",
            f"measured_run_count: {report.measured_run_count}",
            f"total_latency_ms: {_optional(report.total_latency_ms)}",
            f"total_input_tokens: {_optional(report.total_input_tokens)}",
            f"total_output_tokens: {_optional(report.total_output_tokens)}",
            f"total_model_calls: {_optional(report.total_model_calls)}",
        )
    )


def main(argv: Sequence[str]) -> int:
    output = Path(argv[0]) if argv else _DEFAULT_OUTPUT
    report = ScenarioRunner().run_all(corpus())
    output.parent.mkdir(parents=True, exist_ok=True)
    report.write_json(output)
    print(_summary(report))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
