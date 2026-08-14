import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict

from aegisdesk.action import ProtectedActionProposal, ResolvedAction
from aegisdesk.agents.escalation import Escalation, EscalationRefused
from aegisdesk.agents.model import Model
from aegisdesk.agents.resolver import Resolver, ResolverResult
from aegisdesk.agents.router import Router, RoutingRefused
from aegisdesk.agents.state import WorkflowPhase, WorkflowState
from aegisdesk.approval import ApprovalDecision
from aegisdesk.audit import AuditEvent
from aegisdesk.backends.approvals import ApprovalStore
from aegisdesk.backends.audit import AuditSink
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.kb import KnowledgeBase
from aegisdesk.backends.tickets import TicketStore
from aegisdesk.domain.enums import (
    ActorType,
    AgentName,
    ApprovalStatus,
    AuditEventType,
    GuardOutcome,
    TicketStatus,
)
from aegisdesk.domain.errors import (
    ApprovalDecisionError,
    IllegalTicketTransitionError,
    SessionAuthenticationError,
)
from aegisdesk.domain.ids import ApprovalId, TicketId, WorkflowId
from aegisdesk.domain.ticket import BODY_MAX_LENGTH, SUBJECT_MAX_LENGTH
from aegisdesk.guard import REFUSAL_MESSAGE, RuntimeGuard
from aegisdesk.session import (
    EmployeeSessionContext,
    ReviewerSessionContext,
    authenticate_employee,
)

# A workflow may take a bounded number of turns, and a single turn a bounded number of
# handoffs. Both fail closed on exhaustion: a request that will not settle is refused rather
# than allowed to loop, which is the cascading-failure control (project.md 13.6). The limits
# are small because the slice's flows settle in one or two steps; a runaway is pathological.
MAX_TURNS: Final = 8
MAX_HANDOFFS: Final = 4

_GENERIC_ANSWER: Final = "your request has been handled"


class TurnResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: WorkflowPhase
    message: str
    workflow_id: WorkflowId
    ticket_id: TicketId | None = None
    approval_id: ApprovalId | None = None
    # The authoritative resolved action, exposed so a reviewer sees the exact operation rather
    # than an agent's summary (project.md 13.5). Present only while a decision is pending.
    pending_action: ResolvedAction | None = None


# Runtime-only correlation for a paused workflow. It holds the claimed identifier (re-
# authenticated on resume, never trusted as identity) and the exact proposal object, so the
# resume hands the guard the same action to re-resolve. It is not a checkpoint and carries no
# session, approval authority, or policy decision.
@dataclass(frozen=True)
class _Pending:
    claimed_id: str
    workflow_id: WorkflowId
    proposal: ProtectedActionProposal


def _subject(message: str) -> str:
    text = message.strip()[:SUBJECT_MAX_LENGTH]
    return text if text else "employee support request"


def _body(message: str) -> str:
    text = message[:BODY_MAX_LENGTH]
    return text if text else "(no message)"


# The smallest deterministic supervisor that runs a request through the controls built in
# S1-S11. It authenticates, routes, and either resolves routine work or proposes privileged
# work through the guard; approval is an explicit reviewer action, and execution goes only
# through guard.execute_approved. It holds no capability of its own and makes no authorization
# decision: every such decision is delegated to the deterministic control plane.
class Supervisor:
    def __init__(
        self,
        *,
        guard: RuntimeGuard,
        approvals: ApprovalStore,
        tickets: TicketStore,
        directory: DirectoryBackend,
        kb: KnowledgeBase,
        model: Model,
        audit: AuditSink,
        clock: Callable[[], datetime],
    ) -> None:
        self._guard = guard
        self._approvals = approvals
        self._tickets = tickets
        self._directory = directory
        self._audit = audit
        self._clock = clock
        self._router = Router(model)
        self._resolver = Resolver(model, kb)
        self._escalation = Escalation(model, guard)
        self._states: dict[WorkflowId, WorkflowState] = {}
        self._pending: dict[ApprovalId, _Pending] = {}

    def handle(self, claimed_id: str, message: str, workflow_id: WorkflowId) -> TurnResult:
        now = self._clock()
        try:
            session = authenticate_employee(claimed_id, self._directory, now)
        except SessionAuthenticationError:
            self._record_refused(workflow_id, "authentication_failed")
            return TurnResult(
                phase=WorkflowPhase.REFUSED, message=REFUSAL_MESSAGE, workflow_id=workflow_id
            )

        state = self._states.get(workflow_id)
        if state is None:
            ticket = self._tickets.create(session.employee_id, _subject(message))
            state = WorkflowState(workflow_id=workflow_id, ticket_id=ticket.ticket_id)
        state = self._store(state.tick_turn())
        if state.turns > MAX_TURNS:
            return self._refuse(state, "max_turns")

        with contextlib.suppress(IllegalTicketTransitionError):
            self._tickets.append_message(
                session.employee_id,
                state.ticket_id,
                ActorType.EMPLOYEE,
                session.employee_id,
                _body(message),
            )
        return self._route(state, session, claimed_id, message)

    def decide(
        self,
        reviewer: ReviewerSessionContext,
        approval_id: ApprovalId,
        decision: ApprovalDecision,
    ) -> TurnResult:
        pending = self._pending.get(approval_id)
        if pending is None:
            self._record_refused(None, "unknown_approval")
            return TurnResult(
                phase=WorkflowPhase.REFUSED,
                message=REFUSAL_MESSAGE,
                workflow_id=WorkflowId("unknown"),
            )
        state = self._states.get(pending.workflow_id)
        if state is None:
            self._record_refused(pending.workflow_id, "unknown_workflow")
            return TurnResult(
                phase=WorkflowPhase.REFUSED,
                message=REFUSAL_MESSAGE,
                workflow_id=pending.workflow_id,
            )

        # The store enforces roster, liveness, and the requester-is-not-the-reviewer rule; any
        # refusal fails closed here as a generic workflow refusal, so a manipulated caller learns
        # nothing from the reply.
        try:
            record = self._approvals.decide(reviewer, approval_id, decision)
        except ApprovalDecisionError:
            return self._refuse(state, "reviewer_decision_refused")

        requester = authenticate_employee(pending.claimed_id, self._directory, self._clock())
        if record.status is not ApprovalStatus.APPROVED:
            self._set_status(requester, state.ticket_id, TicketStatus.REJECTED)
            state = self._store(state.in_phase(WorkflowPhase.REJECTED))
            return TurnResult(
                phase=WorkflowPhase.REJECTED,
                message=REFUSAL_MESSAGE,
                workflow_id=state.workflow_id,
                ticket_id=state.ticket_id,
            )

        outcome = self._guard.execute_approved(
            AgentName.ESCALATION, requester, pending.workflow_id, pending.proposal
        )
        if outcome.outcome is GuardOutcome.EXECUTED:
            self._set_status(requester, state.ticket_id, TicketStatus.RESOLVED)
            state = self._store(state.in_phase(WorkflowPhase.EXECUTED))
            return TurnResult(
                phase=WorkflowPhase.EXECUTED,
                message=outcome.message,
                workflow_id=state.workflow_id,
                ticket_id=state.ticket_id,
                approval_id=approval_id,
            )
        return self._refuse(state, "execution_refused")

    def _route(
        self, state: WorkflowState, session: EmployeeSessionContext, claimed_id: str, message: str
    ) -> TurnResult:
        handoffs = 0
        while True:
            try:
                decision = self._router.classify(message)
            except RoutingRefused as refusal:
                return self._refuse(state, refusal.reason)
            state = self._store(
                state.routed(decision.target, decision.category, decision.risk_tier)
            )
            if decision.target is AgentName.ESCALATION:
                return self._escalate(state, session, claimed_id, message)

            result = self._resolver.handle(message)
            if isinstance(result, ResolverResult):
                return self._resolve(state, session, result)

            # A scope change stops the routine path and returns to the Router rather than
            # answering a request that turned privileged. The handoff budget bounds the bounce.
            handoffs += 1
            state = self._store(state.tick_handoff())
            if handoffs > MAX_HANDOFFS:
                return self._refuse(state, "max_handoffs")

    def _resolve(
        self, state: WorkflowState, session: EmployeeSessionContext, result: ResolverResult
    ) -> TurnResult:
        answer = _body(result.answer) if result.answer else _GENERIC_ANSWER
        with contextlib.suppress(IllegalTicketTransitionError):
            self._tickets.append_message(
                session.employee_id,
                state.ticket_id,
                ActorType.AGENT,
                AgentName.RESOLVER.value,
                answer,
            )
        self._set_status(session, state.ticket_id, TicketStatus.RESOLVED)
        state = self._store(state.in_phase(WorkflowPhase.RESOLVED))
        return TurnResult(
            phase=WorkflowPhase.RESOLVED,
            message=answer,
            workflow_id=state.workflow_id,
            ticket_id=state.ticket_id,
        )

    def _escalate(
        self, state: WorkflowState, session: EmployeeSessionContext, claimed_id: str, message: str
    ) -> TurnResult:
        try:
            outcome, proposal = self._escalation.propose(
                message, session, state.workflow_id, state.ticket_id
            )
        except EscalationRefused as refusal:
            return self._refuse(state, refusal.reason)

        if outcome.outcome is GuardOutcome.AWAITING_APPROVAL:
            assert outcome.approval_id is not None
            self._pending[outcome.approval_id] = _Pending(
                claimed_id=claimed_id, workflow_id=state.workflow_id, proposal=proposal
            )
            self._set_status(session, state.ticket_id, TicketStatus.PENDING_APPROVAL)
            state = self._store(state.in_phase(WorkflowPhase.AWAITING_APPROVAL))
            return TurnResult(
                phase=WorkflowPhase.AWAITING_APPROVAL,
                message=outcome.message,
                workflow_id=state.workflow_id,
                ticket_id=state.ticket_id,
                approval_id=outcome.approval_id,
                pending_action=outcome.resolved,
            )
        if outcome.outcome is GuardOutcome.EXECUTED:
            self._set_status(session, state.ticket_id, TicketStatus.RESOLVED)
            state = self._store(state.in_phase(WorkflowPhase.EXECUTED))
            return TurnResult(
                phase=WorkflowPhase.EXECUTED,
                message=outcome.message,
                workflow_id=state.workflow_id,
                ticket_id=state.ticket_id,
            )
        # A guard refusal is already on the audit trail; the workflow adds nothing and shows the
        # same generic message.
        state = self._store(state.in_phase(WorkflowPhase.REFUSED))
        return TurnResult(
            phase=WorkflowPhase.REFUSED,
            message=REFUSAL_MESSAGE,
            workflow_id=state.workflow_id,
            ticket_id=state.ticket_id,
        )

    def _refuse(self, state: WorkflowState, reason: str) -> TurnResult:
        self._record_refused(state.workflow_id, reason)
        state = self._store(state.in_phase(WorkflowPhase.REFUSED))
        return TurnResult(
            phase=WorkflowPhase.REFUSED,
            message=REFUSAL_MESSAGE,
            workflow_id=state.workflow_id,
            ticket_id=state.ticket_id,
        )

    def _set_status(
        self, session: EmployeeSessionContext, ticket_id: TicketId, status: TicketStatus
    ) -> None:
        # A terminal ticket cannot advance again; that is a no-op here rather than an error, so a
        # second turn on a settled workflow does not raise.
        with contextlib.suppress(IllegalTicketTransitionError):
            self._tickets.set_status(session.employee_id, ticket_id, status)

    def _store(self, state: WorkflowState) -> WorkflowState:
        self._states[state.workflow_id] = state
        return state

    def _record_refused(self, workflow_id: WorkflowId | None, reason: str) -> None:
        # Best-effort, like the guard's non-executing audit path: a refusal must not be blocked
        # by a recording-boundary outage. The reason is a fixed descriptor, never model prose.
        with contextlib.suppress(Exception):
            self._audit.record(
                AuditEvent.build(
                    event_type=AuditEventType.REFUSED,
                    occurred_at=self._clock(),
                    actor_type=ActorType.RUNTIME,
                    workflow_id=workflow_id,
                    outcome=GuardOutcome.REFUSED,
                    refusal_reason=reason,
                )
            )
