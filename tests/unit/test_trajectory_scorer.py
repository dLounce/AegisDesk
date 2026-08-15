import ast
import inspect
from datetime import UTC, datetime

from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.audit import AuditEvent
from aegisdesk.domain.enums import (
    AccessDuration,
    ActorType,
    AgentName,
    ApprovalStatus,
    AuditEventType,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    RiskTier,
)
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId, WorkflowId
from aegisdesk.evaluation import trajectory as trajectory_module
from aegisdesk.evaluation.trajectory import (
    ActionLifecycleCheck,
    AgentPathCheck,
    ForbiddenEvents,
    ObservedTrajectory,
    PhasePathCheck,
    TrajectoryMatch,
    TrajectoryRubric,
    score_trajectory,
)
from aegisdesk.policy import POLICY_VERSION, PolicyDecision

AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)
_WF = WorkflowId("WF")


def _decision(operation: ProtectedOperation, *, duration: AccessDuration | None) -> PolicyDecision:
    return PolicyDecision(
        policy_version=POLICY_VERSION,
        effect=PolicyEffect.REQUIRE_APPROVAL,
        reason=PolicyReason.PRIVILEGED_RESOURCE,
        operation=operation,
        workflow_id=_WF,
        action_id=ActionId("ACT"),
        evaluated_at=AT,
        requester_id=EmployeeId("E1042"),
        resource_id=ResourceId("prod-db"),
        permission=Permission.ADMIN,
        duration=duration,
        risk_tier=RiskTier.HIGH,
    )


def _proposal(action_id: str, operation: ProtectedOperation) -> AuditEvent:
    duration = AccessDuration.EIGHT_HOURS if operation is ProtectedOperation.GRANT_ACCESS else None
    return AuditEvent.build(
        event_type=AuditEventType.PROPOSAL_PERSISTED,
        occurred_at=AT,
        actor_type=ActorType.AGENT,
        workflow_id=_WF,
        action_id=ActionId(action_id),
        decision=_decision(operation, duration=duration),
    )


def _event(event_type: AuditEventType, action_id: str, detail: str | None = None) -> AuditEvent:
    return AuditEvent.build(
        event_type=event_type,
        occurred_at=AT,
        actor_type=ActorType.RUNTIME,
        workflow_id=_WF,
        action_id=ActionId(action_id),
        detail=detail,
    )


def _full_grant_events(action_id: str = "ACT-1") -> tuple[AuditEvent, ...]:
    return (
        _proposal(action_id, ProtectedOperation.GRANT_ACCESS),
        _event(AuditEventType.AWAITING_APPROVAL, action_id),
        _event(AuditEventType.REVIEWER_DECISION, action_id, ApprovalStatus.APPROVED.value),
        _event(AuditEventType.EXECUTED, action_id),
    )


# --- agent path -----------------------------------------------------------------------------


def test_agent_path_exact_pass_and_fail() -> None:
    observed = ObservedTrajectory(
        agents=(AgentName.ROUTER, AgentName.ESCALATION), phases=(), events=()
    )
    ok = TrajectoryRubric(
        agent_path=AgentPathCheck(
            (AgentName.ROUTER, AgentName.ESCALATION), match=TrajectoryMatch.EXACT
        )
    )
    bad = TrajectoryRubric(
        agent_path=AgentPathCheck(
            (AgentName.ROUTER, AgentName.RESOLVER), match=TrajectoryMatch.EXACT
        )
    )
    assert score_trajectory(ok, observed).acceptable
    assert not score_trajectory(bad, observed).acceptable


def test_agent_path_subsequence_tolerates_extra_step() -> None:
    observed = ObservedTrajectory(
        agents=(AgentName.ROUTER, AgentName.RESOLVER, AgentName.ESCALATION), phases=(), events=()
    )
    subseq = TrajectoryRubric(
        agent_path=AgentPathCheck(
            (AgentName.ROUTER, AgentName.ESCALATION), match=TrajectoryMatch.SUBSEQUENCE
        )
    )
    exact = TrajectoryRubric(
        agent_path=AgentPathCheck(
            (AgentName.ROUTER, AgentName.ESCALATION), match=TrajectoryMatch.EXACT
        )
    )
    assert score_trajectory(subseq, observed).acceptable
    assert not score_trajectory(exact, observed).acceptable


# --- phase path -----------------------------------------------------------------------------


def test_phase_path_exact() -> None:
    observed = ObservedTrajectory(
        agents=(), phases=(WorkflowPhase.AWAITING_APPROVAL, WorkflowPhase.EXECUTED), events=()
    )
    ok = TrajectoryRubric(
        phase_path=PhasePathCheck((WorkflowPhase.AWAITING_APPROVAL, WorkflowPhase.EXECUTED))
    )
    bad = TrajectoryRubric(phase_path=PhasePathCheck((WorkflowPhase.EXECUTED,)))
    assert score_trajectory(ok, observed).acceptable
    assert not score_trajectory(bad, observed).acceptable


# --- action lifecycle -----------------------------------------------------------------------


def test_full_grant_lifecycle_passes() -> None:
    observed = ObservedTrajectory(agents=(), phases=(), events=_full_grant_events())
    rubric = TrajectoryRubric(
        action_lifecycles=(ActionLifecycleCheck(ProtectedOperation.GRANT_ACCESS),)
    )
    assert score_trajectory(rubric, observed).acceptable


def test_lifecycle_fails_when_execution_missing() -> None:
    # Proposal + awaiting + approval but no EXECUTED: the full lifecycle is not satisfied.
    events = _full_grant_events()[:-1]
    observed = ObservedTrajectory(agents=(), phases=(), events=events)
    rubric = TrajectoryRubric(
        action_lifecycles=(ActionLifecycleCheck(ProtectedOperation.GRANT_ACCESS),)
    )
    assert not score_trajectory(rubric, observed).acceptable


def test_lifecycle_rejected_status_does_not_satisfy_approved_step() -> None:
    action_id = "ACT-1"
    events = (
        _proposal(action_id, ProtectedOperation.GRANT_ACCESS),
        _event(AuditEventType.AWAITING_APPROVAL, action_id),
        _event(AuditEventType.REVIEWER_DECISION, action_id, ApprovalStatus.REJECTED.value),
    )
    observed = ObservedTrajectory(agents=(), phases=(), events=events)
    approved = TrajectoryRubric(
        action_lifecycles=(
            ActionLifecycleCheck(
                ProtectedOperation.GRANT_ACCESS,
                steps=(
                    AuditEventType.PROPOSAL_PERSISTED,
                    AuditEventType.AWAITING_APPROVAL,
                    AuditEventType.REVIEWER_DECISION,
                ),
                decision_status=ApprovalStatus.APPROVED,
            ),
        )
    )
    rejected = TrajectoryRubric(
        action_lifecycles=(
            ActionLifecycleCheck(
                ProtectedOperation.GRANT_ACCESS,
                steps=(
                    AuditEventType.PROPOSAL_PERSISTED,
                    AuditEventType.AWAITING_APPROVAL,
                    AuditEventType.REVIEWER_DECISION,
                ),
                decision_status=ApprovalStatus.REJECTED,
            ),
        )
    )
    assert not score_trajectory(approved, observed).acceptable
    assert score_trajectory(rejected, observed).acceptable


def test_lifecycle_requires_the_named_operation() -> None:
    observed = ObservedTrajectory(agents=(), phases=(), events=_full_grant_events())
    rubric = TrajectoryRubric(
        action_lifecycles=(ActionLifecycleCheck(ProtectedOperation.REVOKE_ACCESS),)
    )
    result = score_trajectory(rubric, observed)
    assert not result.acceptable
    assert any("no proposal for operation" in c.reason for c in result.checks)


# --- forbidden events + orthogonality -------------------------------------------------------


def test_forbidden_event_present_fails_even_though_execution_succeeded() -> None:
    # The final action executed (a "successful" outcome) but EXECUTED is forbidden here: the
    # trajectory is unacceptable regardless of task success. This is the orthogonality guarantee
    # expressed purely over the scorer.
    observed = ObservedTrajectory(agents=(), phases=(), events=_full_grant_events())
    rubric = TrajectoryRubric(
        forbidden_events=ForbiddenEvents(frozenset({AuditEventType.EXECUTED}))
    )
    result = score_trajectory(rubric, observed)
    assert not result.acceptable
    assert any("forbidden events present" in c.reason for c in result.checks)


def test_forbidden_absent_passes() -> None:
    observed = ObservedTrajectory(agents=(), phases=(WorkflowPhase.RESOLVED,), events=())
    rubric = TrajectoryRubric(
        forbidden_events=ForbiddenEvents(
            frozenset({AuditEventType.EXECUTED, AuditEventType.PROPOSAL_PERSISTED})
        )
    )
    assert score_trajectory(rubric, observed).acceptable


# --- report aggregation ---------------------------------------------------------------------


def test_score_and_acceptable_and_empty_rubric() -> None:
    observed = ObservedTrajectory(
        agents=(AgentName.ROUTER,), phases=(WorkflowPhase.RESOLVED,), events=()
    )
    mixed = TrajectoryRubric(
        agent_path=AgentPathCheck((AgentName.ROUTER,)),  # passes
        phase_path=PhasePathCheck((WorkflowPhase.EXECUTED,)),  # fails
    )
    report = score_trajectory(mixed, observed)
    assert not report.acceptable
    assert report.score == 0.5
    empty = score_trajectory(TrajectoryRubric(), observed)
    assert empty.acceptable
    assert empty.score == 1.0


# --- security guardrail ---------------------------------------------------------------------


def test_trajectory_module_imports_no_control_plane() -> None:
    # A rubric and the scorer are evaluation data + a pure function. The module must not import any
    # control-plane authority (guard, access backend, approval store, session). Checked over actual
    # imports, not prose, so comments may still name these concepts.
    tree = ast.parse(inspect.getsource(trajectory_module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {"aegisdesk.guard", "aegisdesk.session"}
    assert not (imported & forbidden)
    assert not any(module.startswith("aegisdesk.backends") for module in imported)
