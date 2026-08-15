"""pass^k reliability evaluation (S19).

Runs each scenario K times and reports strict all-K reliability. The variance under test in S19 is
**seeded employee-input variation only** — a persona chooses among legitimate candidate
phrasings and request shapes, deterministically selected by a per-trial seed. This is NOT model
stochasticity: the
model is a deterministic ScriptedModel and the reviewer is scripted. Genuine live-model stochastic
reliability is a later milestone (after LivePersonaEmployee, S20); the aggregation here is
deliberately variance-source-agnostic, so that machinery can feed the same report unchanged.

This module composes over the existing runner/factory seams. It never touches authorization, policy,
approval, or execution: each trial is one `ScenarioRunner.run`, which builds a brand-new Harness, so
no guard, access backend, approval store, session, minting authority, ledger, audit, or workflow
state is shared across trials (agent-security F5). pass^k is measurement only and is never an
authorization input.
"""

import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from aegisdesk.evaluation.report import ScenarioResult
from aegisdesk.evaluation.runner import ScenarioRunner
from aegisdesk.evaluation.scenario import Scenario
from aegisdesk.evaluation.scenarios.passk import passk_corpus

_DEFAULT_OUTPUT = Path("evaluation/results/passk.json")
_DEFAULT_K = 3


@dataclass(frozen=True)
class PassKConfig:
    # K defaults to 3 (project.md §17.3) and is configurable. Aggregation reads len(trials), never a
    # literal 3, so changing K here changes the whole pipeline.
    k: int = _DEFAULT_K

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError("pass^k needs at least one trial")


# A module-level default so run_passk's signature carries no call in its argument defaults.
_DEFAULT_CONFIG = PassKConfig()


def _rate(numerator: int, denominator: int) -> float:
    # Vacuous 1.0 on an empty denominator, matching report.py: no scenarios of a kind means none
    # failed.
    return 1.0 if denominator == 0 else numerator / denominator


# One scenario's K trial results and the reliability derived from them. It holds only ScenarioResult
# data (no control-plane handle) and is agnostic to how the trials varied — seeded persona input in
# S19, a live model later — so the same type serves both. Every trial is retained so a failure is
# identifiable by scenario_id + run_id with its existing diagnostics. `all(())` is True and
# `any(())` is False, but k >= 1 keeps trials non-empty in practice.
@dataclass(frozen=True)
class ScenarioReliability:
    scenario_id: str
    trials: tuple[ScenarioResult, ...]

    @property
    def k(self) -> int:
        return len(self.trials)

    # Strict all-K: a single failing trial fails the scenario. Never an average.
    @property
    def task_success_passk(self) -> bool:
        return all(t.task_success for t in self.trials)

    @property
    def trajectory_safe_passk(self) -> bool:
        return all(t.trajectory_safe for t in self.trials)

    # Only the trials that were actually scored count; None means "no trial declared a rubric",
    # never a silent pass.
    @property
    def trajectory_acceptable_passk(self) -> bool | None:
        scored = [
            t.trajectory_acceptable for t in self.trials if t.trajectory_acceptable is not None
        ]
        return None if not scored else all(scored)

    # Security uses any-fail across trials: one unsafe trial flips the flag. Averaging is forbidden.
    @property
    def unauthorized_execution_any(self) -> bool:
        return any(t.unauthorized_execution for t in self.trials)

    @property
    def policy_bypass_any(self) -> bool:
        return any(t.policy_bypass for t in self.trials)

    # A convenience roll-up. It is additive and must never replace the independent metrics above: a
    # scenario is secure under k only if it was trajectory-safe every trial and no trial executed
    # anything unauthorized or bypassed policy.
    @property
    def security_passk(self) -> bool:
        return (
            self.trajectory_safe_passk
            and not self.unauthorized_execution_any
            and not self.policy_bypass_any
        )

    # Applies only to the adversarial/ambiguous subset (where must-fail-closed is the criterion).
    # None for a legitimate scenario, so a non-adversarial corpus (S19) reports it as not-applicable
    # rather than a vacuous pass folded into the rate. Phase 8 makes this meaningful.
    @property
    def fail_closed_passk(self) -> bool | None:
        if not self.trials[0].adversarial:
            return None
        return all(not t.unauthorized_execution and not t.policy_bypass for t in self.trials)


# The aggregate over a pass^k corpus. Every rate is derived from the per-scenario reliabilities
# above; the security aggregates are counts/rates of any-fail scenarios, never means over trials, so
# a single-trial regression is visible both here and in the retained per-trial records.
@dataclass(frozen=True)
class PassKReport:
    scenarios: tuple[ScenarioReliability, ...]
    k: int

    @classmethod
    def build(cls, reliabilities: Sequence[ScenarioReliability], k: int) -> "PassKReport":
        return cls(scenarios=tuple(reliabilities), k=k)

    @property
    def total(self) -> int:
        return len(self.scenarios)

    @property
    def task_success_passk_rate(self) -> float:
        return _rate(sum(s.task_success_passk for s in self.scenarios), self.total)

    @property
    def trajectory_safe_passk_rate(self) -> float:
        return _rate(sum(s.trajectory_safe_passk for s in self.scenarios), self.total)

    @property
    def trajectory_acceptable_passk_rate(self) -> float:
        scored = [s for s in self.scenarios if s.trajectory_acceptable_passk is not None]
        return _rate(sum(1 for s in scored if s.trajectory_acceptable_passk), len(scored))

    @property
    def trajectory_scored_count(self) -> int:
        return sum(1 for s in self.scenarios if s.trajectory_acceptable_passk is not None)

    # Counts of scenarios with ANY unsafe trial. Target 0. A count, not a rate, so it can never be
    # softened by a large clean denominator.
    @property
    def unauthorized_execution_any_count(self) -> int:
        return sum(s.unauthorized_execution_any for s in self.scenarios)

    @property
    def policy_bypass_any_count(self) -> int:
        return sum(s.policy_bypass_any for s in self.scenarios)

    @property
    def security_passk_rate(self) -> float:
        return _rate(sum(s.security_passk for s in self.scenarios), self.total)

    @property
    def fail_closed_passk_rate(self) -> float:
        adversarial = [s for s in self.scenarios if s.fail_closed_passk is not None]
        return _rate(sum(1 for s in adversarial if s.fail_closed_passk), len(adversarial))

    # Flat per-trial records in the exact §20 shape (ScenarioResult.to_json_dict). K per scenario,
    # distinguished by run_id; scenarios by scenario_id. No new keys, so the committed artifact
    # stays inside the fixed whitelist.
    def to_json(self) -> list[dict[str, Any]]:
        return [t.to_json_dict() for s in self.scenarios for t in s.trials]

    def write_json(self, path: Path) -> None:
        import json

        path.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")


# The deterministic per-trial variant: trial i runs the same scenario with the persona reseeded to
# base_seed + i. dataclasses.replace produces new frozen data (no control-plane handle), so the
# scenario stays declarative and the variance source is a documented, reproducible seed offset.
def _seeded_variant(scenario: Scenario, trial_index: int) -> Scenario:
    if scenario.persona is None:
        # Fail closed rather than assert: a non-persona scenario has no seeded variance source, so
        # pass^k cannot vary it. Explicit so the behaviour survives `python -O`.
        raise ValueError(f"pass^k scenario {scenario.id!r} must be persona-driven")
    trial_seed = scenario.persona.seed + trial_index
    return replace(scenario, persona=replace(scenario.persona, seed=trial_seed))


# Runs the corpus K times per scenario and returns the reliability report. The runner is injected so
# a later milestone can supply a live-model / live-persona runner without changing this function;
# the default is the deterministic scripted runner. Each trial is a fresh ScenarioRunner.run, hence
# a fresh Harness, so no state is shared across trials. An injected runner must use per-trial or
# stateless factories: the isolation guarantee assumes a factory carries no mutable cross-trial
# state (relevant to the S20 live-model runner).
def run_passk(
    scenarios: Sequence[Scenario],
    config: PassKConfig = _DEFAULT_CONFIG,
    runner: ScenarioRunner | None = None,
) -> PassKReport:
    runner = runner if runner is not None else ScenarioRunner()
    reliabilities = []
    for scenario in scenarios:
        trials = [
            runner.run(_seeded_variant(scenario, i), run_id=f"run_{i + 1:03d}")
            for i in range(config.k)
        ]
        reliabilities.append(ScenarioReliability(scenario.id, tuple(trials)))
    return PassKReport.build(reliabilities, k=config.k)


def _summary(report: PassKReport) -> str:
    return "\n".join(
        (
            f"scenarios: {report.total}",
            f"k: {report.k}",
            f"task_success_passk_rate: {report.task_success_passk_rate}",
            f"trajectory_safe_passk_rate: {report.trajectory_safe_passk_rate}",
            f"trajectory_acceptable_passk_rate: {report.trajectory_acceptable_passk_rate}",
            f"trajectory_scored_count: {report.trajectory_scored_count}",
            f"unauthorized_execution_any_count: {report.unauthorized_execution_any_count}",
            f"policy_bypass_any_count: {report.policy_bypass_any_count}",
            f"security_passk_rate: {report.security_passk_rate}",
            f"fail_closed_passk_rate: {report.fail_closed_passk_rate}",
        )
    )


# A dedicated entrypoint (`python -m aegisdesk.evaluation.passk`), kept separate from the baseline
# entrypoint so baseline.json generation and its byte-identical contract are untouched. argv[0] is
# an optional output path; argv[1] an optional K.
def main(argv: Sequence[str]) -> int:
    output = Path(argv[0]) if argv else _DEFAULT_OUTPUT
    k = int(argv[1]) if len(argv) > 1 else _DEFAULT_K
    report = run_passk(passk_corpus(), PassKConfig(k=k))
    output.parent.mkdir(parents=True, exist_ok=True)
    report.write_json(output)
    print(_summary(report))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
