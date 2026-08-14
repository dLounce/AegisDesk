from dataclasses import dataclass

from aegisdesk.agents.model import Model, ModelRequest, ModelResponse, ScriptedModel
from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.domain.enums import AgentName
from aegisdesk.domain.ids import WorkflowId
from aegisdesk.evaluation.harness import Harness
from aegisdesk.evaluation.runner import ScenarioRunner, summarize_telemetry
from aegisdesk.evaluation.scenario import EmployeeTurn, Scenario


@dataclass
class _Telemetry:
    latency_ms: float
    input_tokens: int
    output_tokens: int


class _RecordingModel:
    def __init__(self) -> None:
        self.seen: list[AgentName] = []

    def respond(self, request: ModelRequest) -> ModelResponse:
        self.seen.append(request.agent)
        return ModelResponse(category="kb_question", risk="low", answer="ok")


def test_harness_defaults_to_scripted_model() -> None:
    harness = Harness({(AgentName.ROUTER, "hi"): ModelResponse(category="kb_question")})
    assert isinstance(harness.model, ScriptedModel)


def test_harness_uses_injected_model() -> None:
    injected: Model = _RecordingModel()
    harness = Harness({}, model=injected)
    assert harness.model is injected
    harness.sup.handle("E1042", "vpn help", WorkflowId("WF-INJ"))
    assert AgentName.ROUTER in injected.seen  # type: ignore[attr-defined]


def test_summarize_telemetry_empty_is_all_none() -> None:
    summary = summarize_telemetry([])
    assert summary == summary.__class__(None, None, None, None)


def test_summarize_telemetry_sums_and_counts() -> None:
    summary = summarize_telemetry([_Telemetry(10.0, 3, 5), _Telemetry(20.0, 4, 6)])
    assert summary.latency_ms == 30.0
    assert summary.input_tokens == 7
    assert summary.output_tokens == 11
    assert summary.model_calls == 2


def test_scripted_scenario_result_has_no_latency() -> None:
    scenario = Scenario(
        id="routine",
        workflow_id=WorkflowId("WF-SCRIPTED"),
        script={(AgentName.ROUTER, "vpn"): ModelResponse(category="routine_support", risk="low")},
        turns=(EmployeeTurn(claimed_id="E1042", message="vpn"),),
        expected_final_phase=WorkflowPhase.RESOLVED,
    )
    result = ScenarioRunner().run(scenario)
    assert result.latency_ms is None
    assert result.model_calls is None
    assert result.to_json_dict()["latency_ms"] is None
    assert result.to_json_dict()["cost_usd"] is None
