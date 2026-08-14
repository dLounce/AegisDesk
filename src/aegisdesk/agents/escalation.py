from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from aegisdesk.action import (
    ModifyPermissionsProposal,
    ProposedAction,
    ProtectedActionProposal,
    RevokeAccessProposal,
)
from aegisdesk.agents.model import Model, ModelRequest, ModelResponse
from aegisdesk.agents.state import InformationSlot
from aegisdesk.domain.enums import AccessDuration, AgentName, Permission, ProtectedOperation
from aegisdesk.domain.ids import ResourceId, TicketId, WorkflowId
from aegisdesk.guard import ProposalOutcome, RuntimeGuard
from aegisdesk.session import EmployeeSessionContext

_OPERATION_BY_NAME: Final[dict[str, ProtectedOperation]] = {o.value: o for o in ProtectedOperation}
_PERMISSION_BY_NAME: Final[dict[str, Permission]] = {p.value: p for p in Permission}
_DURATION_BY_NAME: Final[dict[str, AccessDuration]] = {d.value: d for d in AccessDuration}

# Which employee-suppliable slots each protected operation requires, declared in code rather
# than in configuration (S13 decision 1). A grant needs a duration; revoke and modify remove or
# change an existing permission and carry none. Absence of a required slot is a request for
# clarification; the model never decides that information is optional or complete (decision 2).
_REQUIRED_SLOTS: Final[dict[ProtectedOperation, tuple[InformationSlot, ...]]] = {
    ProtectedOperation.GRANT_ACCESS: (
        InformationSlot.RESOURCE,
        InformationSlot.PERMISSION,
        InformationSlot.DURATION,
    ),
    ProtectedOperation.REVOKE_ACCESS: (InformationSlot.RESOURCE, InformationSlot.PERMISSION),
    ProtectedOperation.MODIFY_PERMISSIONS: (InformationSlot.RESOURCE, InformationSlot.PERMISSION),
}

if set(_REQUIRED_SLOTS) != set(ProtectedOperation):
    raise AssertionError("every protected operation must declare its required slots")

# The raw candidate a slot is read from on the model response. Presence is decided here, in
# code: a candidate that is empty (or whitespace) is missing. A non-empty but invalid candidate
# is not "missing" — it is malformed, and fails closed in _build rather than prompting a
# question, so a compromised model cannot turn a garbage value into a clarification loop.
_SLOT_CANDIDATE: Final[dict[InformationSlot, Callable[[ModelResponse], str]]] = {
    InformationSlot.RESOURCE: lambda r: r.resource_id,
    InformationSlot.PERMISSION: lambda r: r.permission,
    InformationSlot.DURATION: lambda r: r.duration,
}


# Raised when model output cannot be turned into a well-formed proposal at all. Fails closed: an
# unrecognised operation or an invalid (non-empty) permission/duration is refused before it
# reaches the guard. Distinct from a missing slot, which asks the employee rather than refusing.
class EscalationRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# The privileged request is missing information only the employee can supply. Carries the slots
# that are absent so the supervisor can ask for exactly those; carries no model text.
@dataclass(frozen=True)
class ClarificationNeeded:
    missing: tuple[InformationSlot, ...]


# A well-formed proposal reached the guard. The proposal is returned alongside the outcome so
# the supervisor can hand the identical object to guard.execute_approved on resume; the guard
# re-resolves and re-digests it regardless, so nothing here is trusted as authoritative.
@dataclass(frozen=True)
class ProposalMade:
    outcome: ProposalOutcome
    proposal: ProtectedActionProposal


EscalationResult = ClarificationNeeded | ProposalMade


# Proposes privileged work and nothing more. It builds a ProtectedActionProposal from validated
# model output and calls guard.propose; it never calls approvals.decide, never touches the
# access backend, and holds no minting authority. The proposal carries no employee field, so it
# cannot target another employee — the guard resolves the requester from the session. Whether
# the action executes is the guard's decision, reached through policy and human approval.
class Escalation:
    def __init__(self, model: Model, guard: RuntimeGuard) -> None:
        self._model = model
        self._guard = guard

    def propose(
        self,
        message: str,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        ticket_id: TicketId,
    ) -> EscalationResult:
        response = self._model.respond(ModelRequest(agent=AgentName.ESCALATION, message=message))
        operation = _OPERATION_BY_NAME.get(response.operation)
        if operation is None:
            raise EscalationRefused("unknown_operation")
        missing = self._missing_slots(operation, response)
        if missing:
            return ClarificationNeeded(missing)
        proposal = self._build(operation, response, ticket_id)
        outcome = self._guard.propose(AgentName.ESCALATION, session, workflow_id, proposal)
        return ProposalMade(outcome=outcome, proposal=proposal)

    def _missing_slots(
        self, operation: ProtectedOperation, response: ModelResponse
    ) -> tuple[InformationSlot, ...]:
        return tuple(
            slot
            for slot in _REQUIRED_SLOTS[operation]
            if not _SLOT_CANDIDATE[slot](response).strip()
        )

    def _build(
        self, operation: ProtectedOperation, response: ModelResponse, ticket_id: TicketId
    ) -> ProtectedActionProposal:
        permission = _PERMISSION_BY_NAME.get(response.permission)
        if permission is None:
            raise EscalationRefused("unknown_permission")
        resource_id = ResourceId(response.resource_id)

        if operation is ProtectedOperation.GRANT_ACCESS:
            duration = _DURATION_BY_NAME.get(response.duration)
            if duration is None:
                raise EscalationRefused("unknown_duration")
            return ProposedAction(
                resource_id=resource_id,
                permission=permission,
                duration=duration,
                ticket_id=ticket_id,
            )
        if operation is ProtectedOperation.REVOKE_ACCESS:
            return RevokeAccessProposal(
                resource_id=resource_id, permission=permission, ticket_id=ticket_id
            )
        return ModifyPermissionsProposal(
            resource_id=resource_id, permission=permission, ticket_id=ticket_id
        )
