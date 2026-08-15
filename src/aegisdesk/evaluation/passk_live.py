"""Live pass^k reliability evaluation (S21).

Runs the S19 pass^k corpus with BOTH the simulated employee and the SUT agent model backed by real
providers, to measure genuine live-model stochastic reliability. A `ScriptedModel` cannot classify
the employee's free-form live messages, so the agent model must be live for the measurement to be
meaningful; both models are untrusted, and the security guarantee is that the deterministic
authorization boundary (guard, capability, policy, human approval, audit) holds regardless.

This module is orchestration only. It composes the existing runner/factory/pass^k seams and changes
none of them:

* Each trial gets a brand-new `Harness` (fresh guard/access/approval/audit/directory/tickets) via
  `run_passk` → `ScenarioRunner.run`, so no control-plane state crosses trials (agent-security F5).
* The SUT model factory and the employee factory receive only the scenario's `script` / `persona`
  (data), never a guard/access/approval/session/minting/reviewer/policy handle.
* `LivePersonaEmployee` still emits only `(claimed_id, message) | None`, and `LiveModel` output is
  still re-validated and re-authorized downstream; neither can approve, mint, or bypass.

Security metrics stay authoritative and strict: `run_passk`'s any-fail counts mean a single
unauthorized execution or policy bypass in one trial fails the corresponding security result,
independent of the other trials — no averaging can hide it.

Live output is non-deterministic and is NEVER a committed benchmark artifact: the entrypoint writes
diagnostics OUTSIDE the repository by default and refuses to write to the committed
`baseline.json` / `passk.json`. The deterministic `passk.py` / `__main__.py` entrypoints and their
artifacts are untouched.
"""

import json
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisdesk.agents.model import Model, ModelRequest, ModelResponse
from aegisdesk.agents.providers import ChatClient, ChatReply, LiveModel, build_chat_client
from aegisdesk.config import (
    ModelConfigError,
    ModelSettings,
    PersonaModelSettings,
    load_model_settings,
    load_persona_model_settings,
)
from aegisdesk.domain.enums import AgentName
from aegisdesk.evaluation.live_persona import LivePersonaEmployee, PersonaCallTelemetry
from aegisdesk.evaluation.passk import PassKConfig, PassKReport, run_passk
from aegisdesk.evaluation.persona import Persona
from aegisdesk.evaluation.report import ScenarioResult
from aegisdesk.evaluation.runner import EmployeeFactory, ModelFactory, ScenarioRunner
from aegisdesk.evaluation.scenario import (
    EmployeeTurn,
    ReviewerTurn,
    Scenario,
    ScenarioScript,
)
from aegisdesk.evaluation.scenarios.passk import passk_corpus

# Default hard ceiling on total provider calls for one manual run (3 scenarios × K=3, both models
# live). It is a belt-and-suspenders spend guard on top of NON_NEGOTIABLES §9; override explicitly.
_DEFAULT_CALL_BUDGET = 80
_DEFAULT_K = 3


class BudgetExceeded(Exception):
    """Raised when the shared provider-call budget is exhausted. Both LiveModel and
    LivePersonaEmployee catch it internally and fail closed, so exhausting the budget degrades to a
    safe scenario failure (empty/default response) rather than an execution — and no further network
    call is made past the ceiling."""


@dataclass
class CallBudget:
    limit: int
    used: int = 0

    def charge(self) -> None:
        if self.used >= self.limit:
            raise BudgetExceeded(f"provider-call budget of {self.limit} exhausted")
        self.used += 1

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit


# Wraps a transport so every completion is charged against the shared budget before the network call
# is made. Because LiveModel/LivePersonaEmployee already fail closed on any client exception, a
# budget stop becomes a safe default response, never an unhandled error in the workflow.
@dataclass(frozen=True)
class _BudgetedChatClient:
    inner: ChatClient
    budget: CallBudget

    def complete(self, system_prompt: str, user_message: str) -> ChatReply:
        self.budget.charge()
        return self.inner.complete(system_prompt, user_message)


def _require_live(settings: ModelSettings | PersonaModelSettings) -> None:
    # Fail closed before any network object is built: the provider must be explicitly the live one
    # and fully configured. Presence of the key is checked, never its value.
    if not settings.is_live:
        raise ModelConfigError("live pass^k requires an openai_compatible provider selection")
    settings.require_live()


def _live_model_factory(settings: ModelSettings, budget: CallBudget) -> ModelFactory:
    # Fresh LiveModel + fresh budgeted transport per trial (the factory is called once per
    # ScenarioRunner.run), so no client/telemetry state crosses trials (F5). The scenario's script
    # is ignored by a live model; it is accepted only to satisfy the ModelFactory signature.
    def factory(_script: ScenarioScript) -> Model:
        return LiveModel(_BudgetedChatClient(build_chat_client(settings), budget))

    return factory


def _live_employee_factory(
    settings: PersonaModelSettings, budget: CallBudget, collected: list[LivePersonaEmployee]
) -> EmployeeFactory:
    # Fresh LivePersonaEmployee + fresh budgeted transport per trial. `collected` retains each built
    # employee purely so its harness-side telemetry can be aggregated after the run; it is never a
    # control-plane handle and never re-enters a scenario.
    def factory(persona: Persona) -> LivePersonaEmployee:
        client = _BudgetedChatClient(
            build_chat_client(settings, temperature=settings.temperature), budget
        )
        employee = LivePersonaEmployee(persona, client)
        collected.append(employee)
        return employee

    return factory


@dataclass(frozen=True)
class LivePassKResult:
    report: PassKReport
    budget_limit: int
    budget_used: int
    # Employee-side (harness) telemetry, kept strictly separate from the SUT telemetry carried on
    # each ScenarioResult — the two measure different things and must not be conflated (AD-57).
    employee_telemetry: tuple[PersonaCallTelemetry, ...]

    @property
    def budget_exhausted(self) -> bool:
        return self.budget_used >= self.budget_limit


def run_live_passk(
    scenarios: Sequence[Scenario] | None = None,
    k: int = _DEFAULT_K,
    budget_limit: int = _DEFAULT_CALL_BUDGET,
    model_settings: ModelSettings | None = None,
    persona_settings: PersonaModelSettings | None = None,
) -> LivePassKResult:
    scenarios = passk_corpus() if scenarios is None else scenarios
    model_settings = load_model_settings() if model_settings is None else model_settings
    persona_settings = (
        load_persona_model_settings() if persona_settings is None else persona_settings
    )
    _require_live(model_settings)
    _require_live(persona_settings)

    budget = CallBudget(budget_limit)
    employees: list[LivePersonaEmployee] = []
    runner = ScenarioRunner(
        model_factory=_live_model_factory(model_settings, budget),
        employee_factory=_live_employee_factory(persona_settings, budget, employees),
    )
    report = run_passk(scenarios, PassKConfig(k=k), runner=runner)
    telemetry = tuple(entry for employee in employees for entry in employee.telemetry)
    return LivePassKResult(report, budget_limit, budget.used, telemetry)


def run_seeded_passk(
    scenarios: Sequence[Scenario] | None = None, k: int = _DEFAULT_K
) -> PassKReport:
    # The deterministic S19 reference: seeded employee input + scripted model, via the default
    # ScenarioRunner. This is what the committed passk.json records.
    scenarios = passk_corpus() if scenarios is None else scenarios
    return run_passk(scenarios, PassKConfig(k=k))


def comparison_summary(seeded: PassKReport, live: PassKReport) -> str:
    rows: tuple[tuple[str, object, object], ...] = (
        ("scenarios", seeded.total, live.total),
        ("k", seeded.k, live.k),
        ("task_success_passk_rate", seeded.task_success_passk_rate, live.task_success_passk_rate),
        (
            "trajectory_safe_passk_rate",
            seeded.trajectory_safe_passk_rate,
            live.trajectory_safe_passk_rate,
        ),
        (
            "trajectory_acceptable_passk_rate",
            seeded.trajectory_acceptable_passk_rate,
            live.trajectory_acceptable_passk_rate,
        ),
        ("security_passk_rate", seeded.security_passk_rate, live.security_passk_rate),
        (
            "unauthorized_execution_any_count",
            seeded.unauthorized_execution_any_count,
            live.unauthorized_execution_any_count,
        ),
        ("policy_bypass_any_count", seeded.policy_bypass_any_count, live.policy_bypass_any_count),
    )
    lines = ["metric: seeded | live"]
    lines += [f"{name}: {seeded_value} | {live_value}" for name, seeded_value, live_value in rows]
    return "\n".join(lines)


def _telemetry_summary(telemetry: Sequence[PersonaCallTelemetry]) -> dict[str, Any] | None:
    if not telemetry:
        return None
    return {
        "calls": len(telemetry),
        "ok": sum(1 for t in telemetry if t.ok),
        "latency_ms": sum(t.latency_ms for t in telemetry),
        "input_tokens": sum(t.input_tokens for t in telemetry),
        "output_tokens": sum(t.output_tokens for t in telemetry),
    }


def _trial_dict(result: ScenarioResult) -> dict[str, Any]:
    # Richer than the committed §20 whitelist on purpose: this file is never committed, and a
    # stochastic failure must be fully inspectable (which trial, what the employee said, what the
    # SUT cost). Security flags are retained per trial so nothing is averaged away.
    return {
        "run_id": result.run_id,
        "task_success": result.task_success,
        "trajectory_safe": result.trajectory_safe,
        "trajectory_acceptable": result.trajectory_acceptable,
        "unauthorized_execution": result.unauthorized_execution,
        "policy_bypass": result.policy_bypass,
        "executed": result.executed,
        "sut_latency_ms": result.latency_ms,
        "sut_input_tokens": result.input_tokens,
        "sut_output_tokens": result.output_tokens,
        "sut_model_calls": result.model_calls,
        "transcript": [
            {"actor": e.actor, "identifier": e.identifier, "content": e.content}
            for e in result.transcript
        ],
    }


def diagnostic_json(result: LivePassKResult) -> dict[str, Any]:
    report = result.report
    return {
        "note": "NON-COMMITTED live pass^k diagnostics; non-deterministic (live-model sampling).",
        "k": report.k,
        "budget": {
            "limit": result.budget_limit,
            "used": result.budget_used,
            "exhausted": result.budget_exhausted,
        },
        "employee_telemetry": _telemetry_summary(result.employee_telemetry),
        "scenarios": [
            {
                "scenario_id": reliability.scenario_id,
                "task_success_passk": reliability.task_success_passk,
                "security_passk": reliability.security_passk,
                "unauthorized_execution_any": reliability.unauthorized_execution_any,
                "policy_bypass_any": reliability.policy_bypass_any,
                "trials": [_trial_dict(trial) for trial in reliability.trials],
            }
            for reliability in report.scenarios
        ],
    }


# --- Deterministic regression capture (freeze helper) ------------------------------------------
#
# When a live trial produces a security or reliability failure, an operator can reproduce it
# deterministically: re-run the single scenario once through a recording SUT model to capture the
# exact (agent, message) -> ModelResponse mapping the live model produced, then render that plus the
# employee transcript as a ScriptedModel-backed scenario for HUMAN REVIEW. Nothing here is committed
# automatically — the render returns source text for a person to inspect and add to the corpus.


class _RecordingModel:
    def __init__(self, inner: Model) -> None:
        self._inner = inner
        self.script: dict[tuple[AgentName, str], ModelResponse] = {}

    def respond(self, request: ModelRequest) -> ModelResponse:
        response = self._inner.respond(request)
        self.script[(request.agent, request.message)] = response
        return response

    @property
    def telemetry(self) -> Sequence[Any]:
        return getattr(self._inner, "telemetry", ())


@dataclass(frozen=True)
class CapturedTrial:
    result: ScenarioResult
    script: dict[tuple[AgentName, str], ModelResponse]
    employee_turns: tuple[EmployeeTurn, ...]


def capture_trial(
    scenario: Scenario,
    budget_limit: int = _DEFAULT_CALL_BUDGET,
    model_settings: ModelSettings | None = None,
    persona_settings: PersonaModelSettings | None = None,
) -> CapturedTrial:
    model_settings = load_model_settings() if model_settings is None else model_settings
    persona_settings = (
        load_persona_model_settings() if persona_settings is None else persona_settings
    )
    _require_live(model_settings)
    _require_live(persona_settings)

    budget = CallBudget(budget_limit)
    recorders: list[_RecordingModel] = []
    employees: list[LivePersonaEmployee] = []

    def model_factory(_script: ScenarioScript) -> Model:
        client = _BudgetedChatClient(build_chat_client(model_settings), budget)
        recorder = _RecordingModel(LiveModel(client))
        recorders.append(recorder)
        return recorder

    runner = ScenarioRunner(
        model_factory=model_factory,
        employee_factory=_live_employee_factory(persona_settings, budget, employees),
    )
    result = runner.run(scenario)
    script = recorders[0].script if recorders else {}
    employee_turns = tuple(
        EmployeeTurn(entry.identifier, entry.content)
        for entry in result.transcript
        if entry.actor == "employee"
    )
    return CapturedTrial(result, script, employee_turns)


def _render_response(response: ModelResponse) -> str:
    defaults = ModelResponse()
    parts = [
        f"{name}={getattr(response, name)!r}"
        for name in ModelResponse.model_fields
        if getattr(response, name) != getattr(defaults, name)
    ]
    return "ModelResponse(" + ", ".join(parts) + ")"


def render_scenario_source(captured: CapturedTrial, scenario: Scenario, new_id: str) -> str:
    # Emits a runnable ScriptedModel-backed Scenario reproducing the captured live behaviour, for a
    # human to review before adding it to the offline corpus. Reviewer turns are carried over from
    # the original scenario (reviewers stay scripted/trusted).
    script_lines = [
        f"    (AgentName.{agent.name}, {message!r}): {_render_response(response)},"
        for (agent, message), response in captured.script.items()
    ]
    turn_lines = [
        f"    EmployeeTurn({turn.claimed_id!r}, {turn.message!r}),"
        for turn in captured.employee_turns
    ]
    turn_lines += [
        f"    ReviewerTurn({turn.reviewer_id!r}, ApprovalDecision.{turn.decision.name}),"
        for turn in scenario.turns
        if isinstance(turn, ReviewerTurn)
    ]
    status = (
        "None"
        if scenario.expected_ticket_status is None
        else f"TicketStatus.{scenario.expected_ticket_status.name}"
    )
    return "\n".join(
        [
            "# Frozen from a live pass^k trial for HUMAN REVIEW. Verify before committing.",
            "Scenario(",
            f"    id={new_id!r},",
            f"    workflow_id=WorkflowId({str(scenario.workflow_id)!r}),",
            "    script={",
            *script_lines,
            "    },",
            "    turns=(",
            *turn_lines,
            "    ),",
            f"    expected_final_phase=WorkflowPhase.{scenario.expected_final_phase.name},",
            f"    expected_ticket_status={status},",
            f"    must_not_execute={scenario.must_not_execute!r},",
            ")",
        ]
    )


# --- Entrypoint --------------------------------------------------------------------------------

_COMMITTED_ARTIFACTS = frozenset({"baseline.json", "passk.json"})


def _reject_committed_paths(path: Path) -> None:
    # Never let live, non-deterministic output overwrite a committed benchmark artifact, and keep it
    # out of the tracked results directory entirely.
    parts = set(path.parts)
    if path.name in _COMMITTED_ARTIFACTS or {"evaluation", "results"} <= parts:
        raise ValueError(f"refusing to write live diagnostics to a committed-artifact path: {path}")


def _default_output() -> Path:
    return Path(tempfile.gettempdir()) / f"aegisdesk_passk_live_{int(time.time())}.json"


def main(argv: Sequence[str]) -> int:
    output = Path(argv[0]) if argv else _default_output()
    k = int(argv[1]) if len(argv) > 1 else _DEFAULT_K
    budget = int(argv[2]) if len(argv) > 2 else _DEFAULT_CALL_BUDGET
    _reject_committed_paths(output)

    scenarios = passk_corpus()
    try:
        live = run_live_passk(scenarios, k=k, budget_limit=budget)
    except ModelConfigError as error:
        print(f"live pass^k not run: {error}")
        return 1

    seeded = run_seeded_passk(scenarios, k=k)
    output.write_text(json.dumps(diagnostic_json(live), indent=2), encoding="utf-8")
    print(comparison_summary(seeded, live.report))
    print(f"provider calls used: {live.budget_used}/{live.budget_limit}")
    if live.budget_exhausted:
        print("WARNING: call budget exhausted — live results are truncated and unreliable")
    print(f"wrote live diagnostics (NON-committed, non-deterministic) to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
