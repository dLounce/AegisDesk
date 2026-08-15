from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from aegisdesk.agents.model import Model, ModelRequest, ModelResponse, ScriptedModel
from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.domain.enums import AgentName
from aegisdesk.domain.errors import SessionAuthenticationError
from aegisdesk.domain.ids import ApprovalId, EmployeeId
from aegisdesk.evaluation.harness import Harness
from aegisdesk.evaluation.metrics import (
    is_trajectory_safe,
    task_success,
    unauthorized_action_ids,
)
from aegisdesk.evaluation.report import RunReport, ScenarioResult
from aegisdesk.evaluation.scenario import EmployeeTurn, ReviewerTurn, Scenario, ScenarioScript
from aegisdesk.evaluation.trajectory import ObservedTrajectory, score_trajectory
from aegisdesk.session import authenticate_employee
from aegisdesk.workflow import TurnResult

_DEFAULT_RUN_ID = "run_001"


# Records the ordered sequence of agents the Supervisor invoked, for golden-trajectory scoring. It
# wraps the scenario's model and delegates `respond` unchanged, so it observes which agent was
# invoked without altering any decision. It is evaluation-only: it holds no guard, access, approval,
# or minting handle (the Model protocol exposes none), and the observed agent sequence is never an
# authorization input. `telemetry` is forwarded so an injected measuring model's S16 telemetry still
# reaches the runner through the wrapper.
class _AgentPathRecorder:
    def __init__(self, inner: Model) -> None:
        self._inner = inner
        self.agents: list[AgentName] = []

    def respond(self, request: ModelRequest) -> ModelResponse:
        self.agents.append(request.agent)
        return self._inner.respond(request)

    @property
    def telemetry(self) -> Sequence["_CallTelemetry"]:
        return getattr(self._inner, "telemetry", ())


# Builds the model that drives one scenario. It receives only the scenario's declarative script —
# data, never the guard, access backend, or minting key — and returns a fresh Model. This is the
# runner's model-injection seam: a caller supplies a factory (e.g. one that returns a live provider
# for a measured run) at ScenarioRunner construction, not on the Scenario, so untrusted scenario
# data can never inject a model object into the control plane (DESIGN AD-53, agent-security F1/F3).
ModelFactory = Callable[[ScenarioScript], Model]


# The default seam: a deterministic ScriptedModel rebuilt from the scenario's own script. Identical
# to what Harness constructs on its own, so the default run stays byte-for-byte reproducible and
# unmeasured (a ScriptedModel records no telemetry).
def scripted_model_factory(script: ScenarioScript) -> Model:
    return ScriptedModel(dict(script))


# What summarize_telemetry reads off each recorded model call. A structural type, so a live model's
# CallTelemetry matches without the evaluation package importing the model layer.
class _CallTelemetry(Protocol):
    latency_ms: float
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class TelemetrySummary:
    latency_ms: float | None
    input_tokens: int | None
    output_tokens: int | None
    model_calls: int | None


# Aggregates the per-call telemetry a live model recorded while driving one scenario. No telemetry
# (a deterministic scripted run) summarizes to all-None — "not measured", never zero — so cost and
# latency reporting can tell an unmeasured run from a genuinely free one.
def summarize_telemetry(telemetry: Sequence[_CallTelemetry]) -> TelemetrySummary:
    if not telemetry:
        return TelemetrySummary(None, None, None, None)
    return TelemetrySummary(
        latency_ms=sum(t.latency_ms for t in telemetry),
        input_tokens=sum(t.input_tokens for t in telemetry),
        output_tokens=sum(t.output_tokens for t in telemetry),
        model_calls=len(telemetry),
    )


# Executes scenarios deterministically through the real control plane and scores them. Each
# scenario gets a brand-new Harness — fresh backends, guard, supervisor, and freshly-loaded seeds
# — so no ledger, approval, ticket, workflow, or audit state leaks between scenarios
# (agent-security F5). The runner passes a scenario only its declared turns; it never hands scenario
# data the guard, the access backend, or the minting key.
class ScenarioRunner:
    # A fresh model is built per scenario from the factory, so telemetry — like every other backend
    # — never leaks between scenarios (agent-security F5). The default factory is scripted and
    # measures nothing; a caller injects a measuring factory only for a deliberate live run.
    def __init__(self, model_factory: ModelFactory = scripted_model_factory) -> None:
        self._model_factory = model_factory

    def run(self, scenario: Scenario, run_id: str = _DEFAULT_RUN_ID) -> ScenarioResult:
        # A fresh recorder per scenario wraps the fresh model, so the observed agent path — like
        # every backend — never leaks between scenarios.
        recorder = _AgentPathRecorder(self._model_factory(scenario.script))
        harness = Harness(scenario.script, model=recorder)
        final, phases = self._drive(harness, scenario)

        owner_id = self._owner(harness, scenario)
        succeeded = task_success(
            final,
            scenario.expected_final_phase,
            scenario.expected_ticket_status,
            harness.tickets,
            owner_id,
        )
        trajectory_safe = is_trajectory_safe(harness.audit.events())
        unauthorized = bool(
            unauthorized_action_ids(harness.access, harness.approvals, scenario.workflow_id)
        )
        executed = bool(harness.access.executed_action_ids())
        # A scenario that must not execute but did — even under a wrongly-obtained approval — is a
        # policy bypass, as is any unauthorized execution anywhere.
        policy_bypass = unauthorized or (scenario.must_not_execute and executed)

        # Golden-trajectory acceptability, scored from the observed path only. None when the
        # scenario declares no rubric ("not evaluated", never silently "acceptable"). Independent of
        # task_success and of every security metric above: a forbidden path is unacceptable even
        # when the final state is correct.
        trajectory_acceptable: bool | None = None
        if scenario.rubric is not None:
            observed = ObservedTrajectory(
                agents=tuple(recorder.agents),
                phases=phases,
                events=tuple(harness.audit.events()),
            )
            trajectory_acceptable = score_trajectory(scenario.rubric, observed).acceptable

        # Telemetry is present only when a live model drove the harness; a scripted run has none.
        telemetry: Sequence[_CallTelemetry] = getattr(harness.model, "telemetry", ())
        metrics = summarize_telemetry(telemetry)

        return ScenarioResult(
            scenario_id=scenario.id,
            run_id=run_id,
            task_success=succeeded,
            trajectory_safe=trajectory_safe,
            policy_bypass=policy_bypass,
            unauthorized_execution=unauthorized,
            adversarial=scenario.adversarial,
            executed=executed,
            trajectory_acceptable=trajectory_acceptable,
            latency_ms=metrics.latency_ms,
            input_tokens=metrics.input_tokens,
            output_tokens=metrics.output_tokens,
            model_calls=metrics.model_calls,
        )

    def run_all(self, scenarios: Sequence[Scenario], run_id: str = _DEFAULT_RUN_ID) -> RunReport:
        return RunReport.build([self.run(scenario, run_id) for scenario in scenarios])

    def _drive(
        self, harness: Harness, scenario: Scenario
    ) -> tuple[TurnResult, tuple[WorkflowPhase, ...]]:
        final: TurnResult | None = None
        pending_approval: ApprovalId | None = None
        # The ordered per-turn terminal phase — the authoritative phase path used for trajectory
        # scoring (clarification, scope-change reroute, approval, rejection are all visible here).
        phases: list[WorkflowPhase] = []
        for turn in scenario.turns:
            if isinstance(turn, EmployeeTurn):
                final = harness.sup.handle(turn.claimed_id, turn.message, scenario.workflow_id)
                if final.approval_id is not None:
                    pending_approval = final.approval_id
            else:
                final = self._decide(harness, turn, pending_approval)
            phases.append(final.phase)
        # A scenario opens with an employee turn (enforced by Scenario), so final is set.
        assert final is not None
        return final, tuple(phases)

    def _decide(
        self, harness: Harness, turn: ReviewerTurn, pending_approval: ApprovalId | None
    ) -> TurnResult:
        if pending_approval is None:
            raise ValueError("a reviewer turn requires a pending approval from an earlier turn")
        return harness.sup.decide(
            harness.reviewer(turn.reviewer_id), pending_approval, turn.decision
        )

    def _owner(self, harness: Harness, scenario: Scenario) -> EmployeeId | None:
        # The workflow owner is the first employee turn's authenticated identity, used only to read
        # the ticket's authoritative status under its owner scoping. An unresolved claim leaves the
        # owner unknown and the ticket-status check is skipped rather than guessed.
        opener = scenario.turns[0]
        assert isinstance(opener, EmployeeTurn)  # guaranteed by Scenario.__post_init__
        try:
            session = authenticate_employee(opener.claimed_id, harness.directory, harness.clock())
        except SessionAuthenticationError:
            return None
        return session.employee_id
