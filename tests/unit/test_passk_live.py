"""Offline tests for the S21 live pass^k orchestration.

Everything here runs offline: `build_chat_client` is monkeypatched to return in-process stubs, so no
provider is contacted. The tests exercise the orchestration guarantees — shared call budget fails
closed, employee telemetry stays separate from SUT telemetry, security is never averaged, live
output never lands on a committed artifact, and a live failure freezes to a deterministic scenario.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import SecretStr

from aegisdesk.agents.model import ModelRequest, ModelResponse, ScriptedModel
from aegisdesk.agents.providers import ChatClient, ChatReply
from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.config import ModelConfigError, ModelProvider, ModelSettings, PersonaModelSettings
from aegisdesk.domain.enums import AgentName, TicketStatus
from aegisdesk.domain.ids import WorkflowId
from aegisdesk.evaluation.live_persona import LivePersonaEmployee
from aegisdesk.evaluation.passk import PassKReport, ScenarioReliability
from aegisdesk.evaluation.passk_live import (
    BudgetExceeded,
    CallBudget,
    LivePassKResult,
    _BudgetedChatClient,
    _live_employee_factory,
    _RecordingModel,
    _reject_committed_paths,
    capture_trial,
    comparison_summary,
    diagnostic_json,
    render_scenario_source,
    run_live_passk,
)
from aegisdesk.evaluation.persona import Persona, PersonaStyle
from aegisdesk.evaluation.report import ScenarioResult
from aegisdesk.evaluation.runner import ScenarioRunner
from aegisdesk.evaluation.scenario import EmployeeTurn, Scenario
from aegisdesk.evaluation.scenarios.passk import passk_corpus

SELF = "E1042"
_FIXED_EMPLOYEE_MESSAGE = "my vpn will not connect"


def _model_settings() -> ModelSettings:
    return ModelSettings(
        provider=ModelProvider.OPENAI_COMPATIBLE, model_name="sut", api_key=SecretStr("k")
    )


def _persona_settings() -> PersonaModelSettings:
    return PersonaModelSettings(
        provider=ModelProvider.OPENAI_COMPATIBLE, model_name="persona", api_key=SecretStr("k")
    )


@dataclass
class _EmployeeStub:
    """A stub employee transport: always returns one fixed benign message."""

    calls: int = 0

    def complete(self, system_prompt: str, user_message: str) -> ChatReply:
        self.calls += 1
        return ChatReply(content=_FIXED_EMPLOYEE_MESSAGE, input_tokens=3, output_tokens=4)


@dataclass
class _SutStub:
    """A stub SUT transport: classifies by the role line LiveModel puts in the prompt, so the
    routine VPN scenario routes Router -> Resolver -> resolved without any provider."""

    calls: int = 0

    def complete(self, system_prompt: str, user_message: str) -> ChatReply:
        self.calls += 1
        first_line = user_message.splitlines()[0]
        if "router" in first_line:
            response = ModelResponse(category="routine_support", risk="low")
        elif "resolver" in first_line:
            response = ModelResponse(category="routine_support", answer="reconnect the vpn")
        else:
            response = ModelResponse()
        return ChatReply(content=response.model_dump_json(), input_tokens=9, output_tokens=5)


def _branching_build_chat_client(
    building_employee: list[_EmployeeStub],
) -> Callable[..., ChatClient]:
    # Distinguishes the two callers by the temperature the employee factory passes: SUT builds with
    # temperature=None, the employee builds with a float.
    def build(config: object, *, temperature: float | None = None) -> ChatClient:
        if temperature is None:
            return _SutStub()
        stub = _EmployeeStub()
        building_employee.append(stub)
        return stub

    return build


def _routine_scenario() -> Scenario:
    return passk_corpus()[0]


# --- Call budget ------------------------------------------------------------------------------


def test_call_budget_charges_then_fails_closed() -> None:
    budget = CallBudget(limit=2)
    budget.charge()
    budget.charge()
    assert budget.used == 2
    with pytest.raises(BudgetExceeded):
        budget.charge()
    assert budget.exhausted is True


def test_budgeted_client_makes_no_call_once_exhausted() -> None:
    inner = _EmployeeStub()
    budget = CallBudget(limit=1)
    client = _BudgetedChatClient(inner, budget)
    client.complete("s", "u")
    assert inner.calls == 1
    with pytest.raises(BudgetExceeded):
        client.complete("s", "u")
    assert inner.calls == 1  # no network call past the ceiling


def test_employee_over_budget_fails_safe_to_empty_message() -> None:
    budget = CallBudget(limit=0)  # nothing allowed
    employee = LivePersonaEmployee(_persona(), _BudgetedChatClient(_EmployeeStub(), budget))
    claimed_id, message = employee.opening()
    assert claimed_id == SELF
    assert message == ""  # budget stop degrades to a safe empty message, never an execution


def _persona() -> Persona:
    return Persona(
        id="p", claimed_id=SELF, openings=("seed",), goal="fix vpn", style=PersonaStyle.TERSE
    )


# --- Employee factory: fresh instances + telemetry retention ----------------------------------


def test_employee_factory_builds_fresh_instances_and_collects_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built: list[_EmployeeStub] = []
    monkeypatch.setattr(
        "aegisdesk.evaluation.passk_live.build_chat_client",
        _branching_build_chat_client(built),
    )
    collected: list[LivePersonaEmployee] = []
    factory = _live_employee_factory(_persona_settings(), CallBudget(10), collected)
    first = factory(_persona())
    second = factory(_persona())
    assert isinstance(first, LivePersonaEmployee)
    assert first is not second
    assert collected == [first, second]


# --- Committed-artifact protection ------------------------------------------------------------


def test_reject_committed_paths_blocks_benchmarks(tmp_path: Path) -> None:
    for bad in (
        Path("evaluation/results/baseline.json"),
        Path("evaluation/results/passk.json"),
        Path("some/dir/evaluation/results/whatever.json"),
    ):
        with pytest.raises(ValueError):
            _reject_committed_paths(bad)
    _reject_committed_paths(tmp_path / "live.json")  # an out-of-repo path is fine


# --- Require-live fail closed ------------------------------------------------------------------


def test_run_live_passk_requires_live_provider() -> None:
    scripted = ModelSettings()  # default scripted provider
    with pytest.raises(ModelConfigError):
        run_live_passk(
            [_routine_scenario()], model_settings=scripted, persona_settings=_persona_settings()
        )


# --- End-to-end offline pipeline ---------------------------------------------------------------


def test_run_live_passk_offline_routine_is_reliable_and_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built: list[_EmployeeStub] = []
    monkeypatch.setattr(
        "aegisdesk.evaluation.passk_live.build_chat_client",
        _branching_build_chat_client(built),
    )
    result = run_live_passk(
        [_routine_scenario()],
        k=2,
        budget_limit=80,
        model_settings=_model_settings(),
        persona_settings=_persona_settings(),
    )
    report = result.report
    assert report.total == 1
    assert report.task_success_passk_rate == 1.0
    assert report.unauthorized_execution_any_count == 0
    assert report.policy_bypass_any_count == 0
    assert report.security_passk_rate == 1.0
    assert result.budget_used > 0
    assert result.budget_used <= 80
    # Employee telemetry is captured and kept separate from SUT ScenarioResult telemetry.
    assert len(result.employee_telemetry) >= 2  # at least one opening per trial


def test_diagnostic_json_preserves_per_trial_security_flags() -> None:
    # A failing trial among clean ones must remain visible, never averaged away.
    clean = ScenarioResult("s", "run_001", True, True, False, False)
    breach = ScenarioResult(
        "s", "run_002", True, True, policy_bypass=True, unauthorized_execution=True, executed=True
    )
    report = PassKReport.build([ScenarioReliability("s", (clean, breach))], k=2)
    payload = diagnostic_json(LivePassKResult(report, 80, 6, ()))
    scenario = payload["scenarios"][0]
    assert scenario["security_passk"] is False
    assert scenario["unauthorized_execution_any"] is True
    assert scenario["policy_bypass_any"] is True
    assert [t["run_id"] for t in scenario["trials"]] == ["run_001", "run_002"]


def test_comparison_summary_reports_both_sides() -> None:
    seeded = PassKReport.build(
        [ScenarioReliability("s", (ScenarioResult("s", "run_001", True, True, False, False),))], k=1
    )
    live = PassKReport.build(
        [ScenarioReliability("s", (ScenarioResult("s", "run_001", False, True, False, False),))],
        k=1,
    )
    summary = comparison_summary(seeded, live)
    assert "seeded | live" in summary
    assert "task_success_passk_rate" in summary
    assert "unauthorized_execution_any_count" in summary


# --- Recording model + freeze round trip -------------------------------------------------------


def test_recording_model_captures_agent_message_responses() -> None:
    inner = ScriptedModel({(AgentName.ROUTER, "x"): ModelResponse(category="routine_support")})
    recorder = _RecordingModel(inner)
    response = recorder.respond(ModelRequest(agent=AgentName.ROUTER, message="x"))
    assert response.category == "routine_support"
    assert recorder.script == {(AgentName.ROUTER, "x"): ModelResponse(category="routine_support")}


def test_capture_and_freeze_reproduces_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[_EmployeeStub] = []
    monkeypatch.setattr(
        "aegisdesk.evaluation.passk_live.build_chat_client",
        _branching_build_chat_client(built),
    )
    scenario = _routine_scenario()
    captured = capture_trial(
        scenario,
        budget_limit=80,
        model_settings=_model_settings(),
        persona_settings=_persona_settings(),
    )
    assert captured.script  # the live SUT's observed (agent, message) -> response mapping
    assert captured.employee_turns == (EmployeeTurn(SELF, _FIXED_EMPLOYEE_MESSAGE),)

    # Rendered source is for human review and names the observed input and agents.
    source = render_scenario_source(captured, scenario, "frozen_routine")
    assert _FIXED_EMPLOYEE_MESSAGE in source
    assert "AgentName.ROUTER" in source
    assert "Scenario(" in source

    # The captured script + employee turns reproduce the outcome deterministically with a
    # ScriptedModel (no provider), which is the point of the freeze helper.
    reproduction = Scenario(
        id="frozen_routine",
        workflow_id=WorkflowId("PASSK-ROUTINE-FROZEN"),
        script=dict(captured.script),
        turns=captured.employee_turns,
        expected_final_phase=WorkflowPhase.RESOLVED,
        expected_ticket_status=TicketStatus.RESOLVED,
    )
    result = ScenarioRunner().run(reproduction)
    assert result.task_success is True
    assert result.executed is False
    assert result.unauthorized_execution is False
