from typing import Final

from aegisdesk.action import (
    ModifyPermissionsProposal,
    ProposedAction,
    ProtectedActionProposal,
    RevokeAccessProposal,
)
from aegisdesk.agents.model import Model, ModelRequest, ModelResponse
from aegisdesk.domain.enums import AccessDuration, AgentName, Permission, ProtectedOperation
from aegisdesk.domain.ids import ResourceId, TicketId, WorkflowId
from aegisdesk.guard import ProposalOutcome, RuntimeGuard
from aegisdesk.session import EmployeeSessionContext

_OPERATION_BY_NAME: Final[dict[str, ProtectedOperation]] = {o.value: o for o in ProtectedOperation}
_PERMISSION_BY_NAME: Final[dict[str, Permission]] = {p.value: p for p in Permission}
_DURATION_BY_NAME: Final[dict[str, AccessDuration]] = {d.value: d for d in AccessDuration}


# Raised when model output cannot be turned into a well-formed proposal. Fails closed: an
# unrecognised operation, permission, or duration is refused before it reaches the guard, so a
# malformed privileged request never becomes a proposal.
class EscalationRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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
    ) -> tuple[ProposalOutcome, ProtectedActionProposal]:
        # Returns the built proposal alongside the outcome so the supervisor can hand the exact
        # same object to guard.execute_approved on resume. The guard re-resolves and re-digests
        # it regardless, so nothing here is trusted; returning it just avoids rebuilding it from
        # a second model call whose output could differ.
        response = self._model.respond(ModelRequest(agent=AgentName.ESCALATION, message=message))
        proposal = self._build(response, ticket_id)
        outcome = self._guard.propose(AgentName.ESCALATION, session, workflow_id, proposal)
        return outcome, proposal

    def _build(self, response: ModelResponse, ticket_id: TicketId) -> ProtectedActionProposal:
        operation = _OPERATION_BY_NAME.get(response.operation)
        if operation is None:
            raise EscalationRefused("unknown_operation")
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
