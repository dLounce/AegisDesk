from datetime import datetime
from typing import Final, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.action import (
    ProposedAction,
    ResolvedAction,
    compute_argument_digest,
    derive_action_id,
)
from aegisdesk.backends.access import AccessBackend
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.tickets import TicketStore
from aegisdesk.capabilities import REQUIRED_CAPABILITY, holds
from aegisdesk.domain.access import AccessGrant, ExecutionReceipt
from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import (
    AgentName,
    GuardOutcome,
    GuardRefusalReason,
    Permission,
    PolicyEffect,
    RiskTier,
    RiskTierConfiguration,
)
from aegisdesk.domain.errors import AegisDeskError, DomainInvariantError
from aegisdesk.domain.ids import ActionId, ArgumentDigest, TicketId, WorkflowId
from aegisdesk.domain.resource import Resource
from aegisdesk.policy import POLICY_VERSION, PolicyDecision, PolicyRequest, evaluate
from aegisdesk.session import EmployeeSessionContext

# One sentence for the model, whatever the reason. A refusal that named its cause would let a
# compromised agent search the argument space by comparing replies until one combination is
# permitted. The precise reason stays on the outcome record, which is bound for the audit
# trail, not for the conversation.
REFUSAL_MESSAGE: Final = "the requested action is not permitted"
EXECUTION_MESSAGE: Final = "the requested access was granted"


class _Refused(Exception):
    def __init__(self, reason: GuardRefusalReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class ProposalOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: GuardOutcome
    refusal_reason: GuardRefusalReason | None
    # Present once the guard has resolved the proposal. A refusal reached before resolution
    # carries none of them, because copying unresolved values onto a record bound for the audit
    # trail would put a model's arguments where authoritative values belong.
    resolved: ResolvedAction | None
    action_id: ActionId | None
    argument_digest: ArgumentDigest | None
    decision: PolicyDecision | None
    grant: AccessGrant | None
    authorised_at: AwareDatetime | None

    # A property rather than a field, so the text cannot vary by construction site and a
    # refusal cannot be given a more helpful message by a caller that means well.
    @property
    def message(self) -> str:
        return EXECUTION_MESSAGE if self.outcome is GuardOutcome.EXECUTED else REFUSAL_MESSAGE

    @model_validator(mode="after")
    def _outcome_agrees_with_record(self) -> Self:
        if self.outcome is GuardOutcome.EXECUTED:
            required = (
                self.resolved,
                self.action_id,
                self.argument_digest,
                self.decision,
                self.grant,
                self.authorised_at,
            )
            if self.refusal_reason is not None or any(field is None for field in required):
                raise DomainInvariantError("an executed outcome must carry a complete record")
        elif self.refusal_reason is None or self.grant is not None:
            raise DomainInvariantError("a refusal must state a reason and carry no grant")
        return self


def _refused(
    reason: GuardRefusalReason,
    resolved: ResolvedAction | None = None,
    action_id: ActionId | None = None,
    argument_digest: ArgumentDigest | None = None,
    decision: PolicyDecision | None = None,
) -> ProposalOutcome:
    return ProposalOutcome(
        outcome=GuardOutcome.REFUSED,
        refusal_reason=reason,
        resolved=resolved,
        action_id=action_id,
        argument_digest=argument_digest,
        decision=decision,
        grant=None,
        authorised_at=None,
    )


# The single path to a protected operation. It is called from inside the protected tool rather
# than from a workflow node, so no routing decision an agent influences can skip it
# (DESIGN.md AD-1).
#
# Everything the decision depends on is resolved here from an authoritative source. The
# proposal names an operation, a resource identifier, a permission, a duration and a ticket;
# the requester, the resource record, the baseline permission, the risk tier, the action
# identifier and the argument digest are all produced by this class. A caller cannot supply
# any of them, so a self-built Resource or a baseline the directory never issued has no field
# to arrive in.
class RuntimeGuard:
    def __init__(
        self,
        directory: DirectoryBackend,
        catalog: ResourceCatalog,
        tickets: TicketStore,
        risk_tiers: RiskTierConfiguration,
        access: AccessBackend,
    ) -> None:
        self._directory = directory
        self._catalog = catalog
        self._tickets = tickets
        self._risk_tiers = dict(risk_tiers)
        self._access = access
        # Claimed once, at construction. The backend refuses a second claim, so a component
        # loading later cannot acquire the ability to mint a receipt by asking for it.
        self._minting_key = access.claim_minting_authority()

    def propose(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProposedAction,
        now: datetime,
    ) -> ProposalOutcome:
        # Identity is checked before anything else. An object that merely carries an
        # employee_id would otherwise pass every later check, because the directory scopes a
        # read to the requester the caller named — which is exactly the claim the session
        # boundary exists to refuse. The annotation is a promise, not a check, here and on
        # the proposal below, for the same reason policy.evaluate re-checks its argument.
        if not isinstance(session, EmployeeSessionContext):
            return _refused(GuardRefusalReason.UNTRUSTED_SESSION)
        if not isinstance(action, ProposedAction):
            return _refused(GuardRefusalReason.MALFORMED_PROPOSAL)

        # Before any backend read, so a caller without the capability learns nothing about the
        # directory, the catalogue or the ticket store by watching what happens next. An
        # operation with no entry in the registry has no capability that can propose it.
        required = REQUIRED_CAPABILITY.get(action.operation)
        if required is None or not holds(agent, required):
            return _refused(GuardRefusalReason.MISSING_CAPABILITY)

        try:
            requester = self._requester(session)
            self._require_ticket(session, action.ticket_id)
            resource = self._resource(action)
            baseline = self._baseline(session, resource)
            risk_tier = self._risk_tier(resource, action)
        except _Refused as refusal:
            return _refused(refusal.reason)

        resolved = ResolvedAction(
            operation=action.operation,
            requester_id=requester.employee_id,
            resource_id=resource.resource_id,
            permission=action.permission,
            duration=action.duration,
            ticket_id=action.ticket_id,
            workflow_id=workflow_id,
        )
        action_id = derive_action_id(resolved)
        digest = compute_argument_digest(resolved, action_id, POLICY_VERSION)
        decision = evaluate(
            PolicyRequest(
                workflow_id=workflow_id,
                action_id=action_id,
                evaluated_at=now,
                requester=requester,
                resource=resource,
                permission=action.permission,
                duration=action.duration,
                baseline_permission=baseline,
                risk_tier=risk_tier,
            )
        )

        # REQUIRE_APPROVAL and DENY both stop here. An approval record is authoritative state
        # that does not exist yet, and inferring one from the decision would be exactly the
        # authorization the model is not allowed to invent, so an effect other than ALLOW is a
        # refusal with the decision preserved for the audit trail.
        if decision.effect is not PolicyEffect.ALLOW:
            return _refused(
                GuardRefusalReason.POLICY_REFUSED, resolved, action_id, digest, decision
            )

        grant = self._access.grant(
            ExecutionReceipt(
                action_id=action_id,
                requester_id=resolved.requester_id,
                resource_id=resolved.resource_id,
                permission=resolved.permission,
                duration=resolved.duration,
                authorised_at=now,
            ),
            self._minting_key,
        )
        return ProposalOutcome(
            outcome=GuardOutcome.EXECUTED,
            refusal_reason=None,
            resolved=resolved,
            action_id=action_id,
            argument_digest=digest,
            decision=decision,
            grant=grant,
            authorised_at=now,
        )

    def _requester(self, session: EmployeeSessionContext) -> Employee:
        try:
            return self._directory.get_employee(session.employee_id, session.employee_id)
        except AegisDeskError:
            raise _Refused(GuardRefusalReason.UNRESOLVED_REQUESTER) from None

    # Read for its scoping, not for its contents. The store reports a ticket the session does
    # not own as absent, so a proposal that attaches itself to somebody else's ticket stops
    # here rather than reaching a reviewer under a ticket number that misdescribes it.
    def _require_ticket(self, session: EmployeeSessionContext, ticket_id: TicketId) -> None:
        try:
            self._tickets.get(session.employee_id, ticket_id)
        except AegisDeskError:
            raise _Refused(GuardRefusalReason.UNRESOLVED_TICKET) from None

    def _resource(self, action: ProposedAction) -> Resource:
        try:
            return self._catalog.get(action.resource_id)
        except AegisDeskError:
            raise _Refused(GuardRefusalReason.UNRESOLVED_RESOURCE) from None

    def _baseline(self, session: EmployeeSessionContext, resource: Resource) -> Permission | None:
        return self._directory.get_baseline_permission(
            session.employee_id, session.employee_id, resource.resource_id
        )

    def _risk_tier(self, resource: Resource, action: ProposedAction) -> RiskTier:
        tier = self._risk_tiers.get((resource.resource_class, action.permission, action.duration))
        if tier is None:
            raise _Refused(GuardRefusalReason.UNCLASSIFIED_RISK)
        return tier
