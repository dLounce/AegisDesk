import contextlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Final, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.action import (
    ProposedAction,
    ProtectedActionProposal,
    ResolvedAction,
    compute_argument_digest,
    derive_action_id,
)
from aegisdesk.approval import (
    ApprovalRecord,
    decision_tuple,
    effective_status,
    recorded_decision_tuple,
)
from aegisdesk.audit import AuditEvent
from aegisdesk.backends.access import AccessBackend
from aegisdesk.backends.approvals import ApprovalStore
from aegisdesk.backends.audit import AuditSink
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.tickets import TicketStore
from aegisdesk.capabilities import REQUIRED_CAPABILITY, holds
from aegisdesk.domain.access import AccessChange, AccessGrant, DestructiveReceipt, ExecutionReceipt
from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import (
    ActorType,
    AgentName,
    ApprovalStatus,
    AuditEventType,
    GuardOutcome,
    GuardRefusalReason,
    OperationRiskTierConfiguration,
    Permission,
    PolicyEffect,
    ProtectedOperation,
    ReversibilityConfiguration,
    RiskTier,
    RiskTierConfiguration,
)
from aegisdesk.domain.errors import (
    AegisDeskError,
    CurrentAccessMismatchError,
    DomainInvariantError,
    NoCurrentAccessError,
    UncertainDestructiveReplayError,
)
from aegisdesk.domain.ids import ActionId, ApprovalId, ArgumentDigest, TicketId, WorkflowId
from aegisdesk.domain.resource import Resource
from aegisdesk.policy import POLICY_VERSION, PolicyDecision, PolicyRequest, evaluate
from aegisdesk.session import EmployeeSessionContext

# One sentence for the model, whatever the reason. A refusal that named its cause would let a
# compromised agent search the argument space by comparing replies until one combination is
# permitted. The precise reason stays on the outcome record, which is bound for the audit
# trail, not for the conversation.
REFUSAL_MESSAGE: Final = "the requested action is not permitted"
EXECUTION_MESSAGE: Final = "the requested access was granted"
# A destructive operation reports completion without naming the resource or the permission, in
# the same spirit as the grant message. It is a distinct sentence only because "granted" would
# misdescribe a revoke or a modify to the employee.
EXECUTION_CHANGE_MESSAGE: Final = "the requested access change was applied"
# A pending action is told apart from a refused one, which is the one distinction the model is
# allowed to draw. It has to be: the workflow pauses and the employee is told a human is
# looking, and an agent that could not tell the two apart would report a refusal instead. The
# message still names no resource, no policy rule and no reviewer.
PENDING_MESSAGE: Final = "the requested action is waiting on a human decision"

# The record states in which a proposal is gated rather than refused. Written as a permit-list,
# so a status with no entry refuses by default.
_GATED_STATUSES: Final[frozenset[ApprovalStatus]] = frozenset(
    {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
)

# Why a proposal against an existing record was refused. Rejection and lapse are separated
# because they are different events in an audit trail: one is an agent re-proposing an action a
# human turned down, which is on the adversarial list, and the other is an ordinary time-out.
_PROPOSAL_REFUSAL_REASONS: Final[Mapping[ApprovalStatus, GuardRefusalReason]] = {
    ApprovalStatus.REJECTED: GuardRefusalReason.APPROVAL_ALREADY_REJECTED,
    ApprovalStatus.EXPIRED: GuardRefusalReason.APPROVAL_LAPSED,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class _Refused(Exception):
    def __init__(
        self,
        reason: GuardRefusalReason,
        resolved: ResolvedAction | None = None,
        action_id: ActionId | None = None,
        argument_digest: ArgumentDigest | None = None,
        decision: PolicyDecision | None = None,
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.resolved = resolved
        self.action_id = action_id
        self.argument_digest = argument_digest
        self.decision = decision


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
    # Named when an approval record was opened or executed against. A refusal carries none,
    # even one that found a record: the action identifier already names the record
    # deterministically, so an audit line loses nothing and a refused caller learns nothing.
    approval_id: ApprovalId | None
    # A grant is the effect of a grant execution; an access change is the effect of a revoke or a
    # modify. Exactly one is present on an executed outcome, chosen by the operation, and neither
    # on a pending or refused one.
    grant: AccessGrant | None
    access_change: AccessChange | None
    authorised_at: AwareDatetime | None

    # A property rather than a field, so the text cannot vary by construction site and a
    # refusal cannot be given a more helpful message by a caller that means well.
    @property
    def message(self) -> str:
        if self.outcome is GuardOutcome.EXECUTED:
            if self.resolved is not None and self.resolved.operation is not (
                ProtectedOperation.GRANT_ACCESS
            ):
                return EXECUTION_CHANGE_MESSAGE
            return EXECUTION_MESSAGE
        if self.outcome is GuardOutcome.AWAITING_APPROVAL:
            return PENDING_MESSAGE
        return REFUSAL_MESSAGE

    @model_validator(mode="after")
    def _outcome_agrees_with_record(self) -> Self:
        resolution = (self.resolved, self.action_id, self.argument_digest, self.decision)
        if self.outcome is GuardOutcome.EXECUTED:
            if self.refusal_reason is not None or any(field is None for field in resolution):
                raise DomainInvariantError("an executed outcome must carry a complete record")
            if self.authorised_at is None:
                raise DomainInvariantError("an executed outcome must carry its authorisation time")
            # A grant execution carries a grant and no change; a destructive execution the
            # reverse. The operation on the resolved action decides which, so an outcome cannot
            # claim a grant for a revoke or a change for a grant.
            assert self.resolved is not None
            if self.resolved.operation is ProtectedOperation.GRANT_ACCESS:
                if self.grant is None or self.access_change is not None:
                    raise DomainInvariantError("a grant outcome must carry a grant and no change")
            elif self.access_change is None or self.grant is not None:
                raise DomainInvariantError("a destructive outcome must carry a change and no grant")
        elif self.outcome is GuardOutcome.AWAITING_APPROVAL:
            pending = (*resolution, self.approval_id)
            if self.refusal_reason is not None or any(field is None for field in pending):
                raise DomainInvariantError("a pending outcome must name its approval record")
            if self.grant is not None or self.access_change is not None or self.authorised_at:
                raise DomainInvariantError("a pending outcome must carry no effect")
        elif (
            self.refusal_reason is None
            or self.grant is not None
            or self.access_change is not None
            or self.approval_id is not None
        ):
            raise DomainInvariantError("a refusal must state a reason and carry no effect")
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
        approval_id=None,
        grant=None,
        access_change=None,
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
#
# Both entry points run that resolution. `propose` runs it before the workflow pauses and
# `execute_approved` runs it again afterwards, from the same untrusted-shaped inputs, so the
# guarantee holds on the resuming pass as well as on the first (DESIGN.md AD-38).
class RuntimeGuard:
    def __init__(
        self,
        directory: DirectoryBackend,
        catalog: ResourceCatalog,
        tickets: TicketStore,
        risk_tiers: RiskTierConfiguration,
        access: AccessBackend,
        approvals: ApprovalStore,
        audit: AuditSink,
        clock: Callable[[], datetime] = _utc_now,
        operation_risk_tiers: OperationRiskTierConfiguration | None = None,
        reversibility: ReversibilityConfiguration | None = None,
    ) -> None:
        self._directory = directory
        self._catalog = catalog
        self._tickets = tickets
        self._risk_tiers = dict(risk_tiers)
        # Configuration for the destructive operations, kept separate from the grant corpus above
        # because they are keyed differently. Empty by default so a guard built for grant-only use
        # is unchanged; a revoke or a modify with no tier or no reversibility entry fails closed.
        self._operation_risk_tiers = dict(operation_risk_tiers or {})
        self._reversibility = dict(reversibility or {})
        self._access = access
        self._approvals = approvals
        self._audit = audit
        # Injected rather than read from the system clock at each use, and owned here rather
        # than taken per call: approval freshness and grant windows are decided against it, and
        # a caller that supplied the instant could backdate an expiry check or choose the window
        # of every grant it asked for (DESIGN.md AD-42).
        self._clock = clock
        # Claimed once, at construction. The backend refuses a second claim, so a component
        # loading later cannot acquire the ability to mint a receipt by asking.
        self._minting_key = access.claim_minting_authority()

    def propose(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProtectedActionProposal,
    ) -> ProposalOutcome:
        now = self._clock()
        outcome = self._propose(agent, session, workflow_id, action, now)
        self._emit(outcome, workflow_id, now)
        return outcome

    def _propose(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProtectedActionProposal,
        now: datetime,
    ) -> ProposalOutcome:
        try:
            resolved, action_id, digest, decision = self._resolve(
                agent, session, workflow_id, action, now
            )
        except _Refused as refusal:
            return _refused(
                refusal.reason,
                refusal.resolved,
                refusal.action_id,
                refusal.argument_digest,
                refusal.decision,
            )

        if decision.effect is PolicyEffect.ALLOW:
            return self._execute(resolved, action_id, digest, decision, now, approval_id=None)

        # REQUIRE_APPROVAL opens an authoritative record and stops. The record is what a later
        # resume reads; nothing about the effect itself authorises anything, which is why the
        # store is written to rather than the decision being remembered (DESIGN.md AD-39).
        if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
            try:
                record = self._approvals.open(resolved, action_id, digest, decision)
            except AegisDeskError:
                return _refused(
                    GuardRefusalReason.APPROVAL_LIMIT_REACHED,
                    resolved,
                    action_id,
                    digest,
                    decision,
                )
            return self._gated(record, resolved, action_id, digest, decision, now)

        # DENY writes nothing. A denied action reaching a reviewer would let a human approve
        # what policy already refused, which is the precedence the rule order exists to keep.
        return _refused(GuardRefusalReason.POLICY_REFUSED, resolved, action_id, digest, decision)

    # The resuming pass. It takes what `propose` takes and derives everything again, so a
    # caller cannot hand back a resolved action, an identifier, a digest, a decision or an
    # approval record and have it believed (DESIGN.md AD-34, AD-38).
    def execute_approved(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProtectedActionProposal,
    ) -> ProposalOutcome:
        now = self._clock()
        outcome = self._execute_approved(agent, session, workflow_id, action, now)
        self._emit(outcome, workflow_id, now)
        return outcome

    def _execute_approved(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProtectedActionProposal,
        now: datetime,
    ) -> ProposalOutcome:
        try:
            resolved, action_id, digest, decision = self._resolve(
                agent, session, workflow_id, action, now
            )
            try:
                record = self._approval_for(workflow_id, action_id, digest, decision, now)
            except _Refused as refusal:
                # The resolution survives a refusal reached after it, so an audit line can say
                # which action was refused and under which decision.
                raise _Refused(refusal.reason, resolved, action_id, digest, decision) from None
        except _Refused as refusal:
            return _refused(
                refusal.reason,
                refusal.resolved,
                refusal.action_id,
                refusal.argument_digest,
                refusal.decision,
            )
        return self._execute(resolved, action_id, digest, decision, now, record.approval_id)

    def _resolve(
        self,
        agent: AgentName,
        session: EmployeeSessionContext,
        workflow_id: WorkflowId,
        action: ProtectedActionProposal,
        now: datetime,
    ) -> tuple[ResolvedAction, ActionId, ArgumentDigest, PolicyDecision]:
        # Identity is checked before anything else. An object that merely carries an
        # employee_id would otherwise pass every later check, because the directory scopes a
        # read to the requester the caller named — which is exactly the claim the session
        # boundary exists to refuse. The annotation is a promise, not a check, here and on
        # the proposal below, for the same reason policy.evaluate re-checks its argument.
        if not isinstance(session, EmployeeSessionContext):
            raise _Refused(GuardRefusalReason.UNTRUSTED_SESSION)
        if not isinstance(action, ProtectedActionProposal):
            raise _Refused(GuardRefusalReason.MALFORMED_PROPOSAL)

        # Before any backend read, so a caller without the capability learns nothing about the
        # directory, the catalogue or the ticket store by watching what happens next. An
        # operation with no entry in the registry has no capability that can propose it.
        required = REQUIRED_CAPABILITY.get(action.operation)
        if required is None or not holds(agent, required):
            raise _Refused(GuardRefusalReason.MISSING_CAPABILITY)

        requester = self._requester(session)
        self._require_ticket(session, action.ticket_id)
        resource = self._resource(action)
        baseline = self._baseline(session, resource)
        risk_tier = self._risk_tier(resource, action)

        # Only a grant carries a duration; a revoke or a modify has no field for one, so the
        # resolved action, the canonical form and the policy request all take None.
        duration = action.duration if isinstance(action, ProposedAction) else None
        resolved = ResolvedAction(
            operation=action.operation,
            requester_id=requester.employee_id,
            resource_id=resource.resource_id,
            permission=action.permission,
            duration=duration,
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
                operation=action.operation,
                requester=requester,
                resource=resource,
                permission=action.permission,
                duration=duration,
                baseline_permission=baseline,
                risk_tier=risk_tier,
            )
        )
        return resolved, action_id, digest, decision

    # What an existing record means for a proposal. `open` is insert-if-absent, so a repeated
    # pass over a decided action gets that decision back rather than a fresh pending record —
    # which is what stops a rejection being reset, and is also why the state has to be read
    # here. Reporting AWAITING_APPROVAL for a record that was rejected or has lapsed would tell
    # a workflow to wait for a decision that has already been made or can no longer be made.
    #
    # An approved record still reports AWAITING_APPROVAL, and deliberately with the same
    # sentence as a pending one. The proposing pass never executes, so the action really is
    # still gated here; and a reply that changed the moment a reviewer approved would let an
    # agent re-propose in a loop to learn exactly when its action cleared the gate, which is the
    # oracle every other refusal in this class avoids (DESIGN.md AD-35).
    def _gated(
        self,
        record: ApprovalRecord,
        resolved: ResolvedAction,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
    ) -> ProposalOutcome:
        status = effective_status(record, now)
        if status not in _GATED_STATUSES:
            # .get rather than indexing, so a status without an entry — SUPERSEDED today,
            # anything added later — refuses instead of raising on the fail-closed path.
            reason = _PROPOSAL_REFUSAL_REASONS.get(status, GuardRefusalReason.APPROVAL_NOT_GRANTED)
            return _refused(reason, resolved, action_id, digest, decision)
        return ProposalOutcome(
            outcome=GuardOutcome.AWAITING_APPROVAL,
            refusal_reason=None,
            resolved=resolved,
            action_id=action_id,
            argument_digest=digest,
            decision=decision,
            approval_id=record.approval_id,
            grant=None,
            access_change=None,
            authorised_at=None,
        )

    # Records the trajectory of a completed pass. The executed event is not written here: it is
    # written inside _execute before the grant, where it is fail-closed. Everything recorded here
    # is a non-executing outcome, so a failed write leaves the outcome untouched rather than
    # converting a refusal or a pause into a raised exception. A pending outcome yields two
    # entries — the proposal was persisted and the action is now waiting — and both are keyed, so
    # a replayed pre-pause pass records neither a second time.
    def _emit(self, outcome: ProposalOutcome, workflow_id: WorkflowId, now: datetime) -> None:
        if outcome.outcome is GuardOutcome.EXECUTED:
            return
        with contextlib.suppress(Exception):
            if outcome.outcome is GuardOutcome.AWAITING_APPROVAL:
                self._audit.record(
                    AuditEvent.build(
                        event_type=AuditEventType.PROPOSAL_PERSISTED,
                        occurred_at=now,
                        actor_type=ActorType.RUNTIME,
                        workflow_id=workflow_id,
                        action_id=outcome.action_id,
                        decision=outcome.decision,
                    )
                )
                self._audit.record(
                    AuditEvent.build(
                        event_type=AuditEventType.AWAITING_APPROVAL,
                        occurred_at=now,
                        actor_type=ActorType.RUNTIME,
                        workflow_id=workflow_id,
                        action_id=outcome.action_id,
                        outcome=GuardOutcome.AWAITING_APPROVAL,
                        decision=outcome.decision,
                    )
                )
                return
            reason = None if outcome.refusal_reason is None else outcome.refusal_reason.value
            self._audit.record(
                AuditEvent.build(
                    event_type=AuditEventType.REFUSED,
                    occurred_at=now,
                    actor_type=ActorType.RUNTIME,
                    workflow_id=workflow_id,
                    # None for a refusal reached before resolution; that entry is uncorrelated and
                    # recorded on every genuine attempt rather than deduplicated.
                    action_id=outcome.action_id,
                    outcome=GuardOutcome.REFUSED,
                    refusal_reason=reason,
                    decision=outcome.decision,
                )
            )

    # The five checks a resume runs against the authoritative record. Each fails closed, and
    # the fourth fails closed even when the re-evaluated decision would now permit the action
    # outright: a changed world is a world the reviewer did not authorise.
    def _approval_for(
        self,
        workflow_id: WorkflowId,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
    ) -> ApprovalRecord:
        record = self._approvals.get(workflow_id, action_id)
        if record is None:
            raise _Refused(GuardRefusalReason.NO_APPROVAL_RECORD)
        # Redundant against the key the record was fetched by, and kept because a later store
        # behind a database or a cache is where a key and a row come to disagree.
        if record.workflow_id != workflow_id or record.action_id != action_id:
            raise _Refused(GuardRefusalReason.NO_APPROVAL_RECORD)
        if effective_status(record, now) is not ApprovalStatus.APPROVED:
            raise _Refused(GuardRefusalReason.APPROVAL_NOT_GRANTED)
        if record.argument_digest != digest:
            raise _Refused(GuardRefusalReason.ARGUMENT_DIGEST_MISMATCH)
        if recorded_decision_tuple(record) != decision_tuple(decision):
            raise _Refused(GuardRefusalReason.DECISION_TUPLE_MISMATCH)
        if record.reviewer_id is None or not self._approvals.reviewer_is_eligible(
            record.reviewer_id, record.requester_id
        ):
            raise _Refused(GuardRefusalReason.REVIEWER_NOT_ELIGIBLE)
        return record

    # One executed outcome per operation kind. Grant and the destructive operations both reach
    # execution only through this dispatch, so the resume checks above run identically for each.
    def _execute(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
        approval_id: ApprovalId | None,
    ) -> ProposalOutcome:
        if resolved.operation is ProtectedOperation.GRANT_ACCESS:
            return self._execute_grant(resolved, action_id, digest, decision, now, approval_id)
        return self._execute_destructive(resolved, action_id, digest, decision, now, approval_id)

    # The executed event is written here, before the grant is minted, so it is fail-closed: if
    # the recording boundary raises, the exception propagates and no grant is issued. The write
    # is idempotent under the action identifier, so a replayed resume records one executed event
    # rather than two. Every other event the guard records is a non-executing outcome written
    # best-effort in _emit; only this one gates the grant.
    def _execute_grant(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
        approval_id: ApprovalId | None,
    ) -> ProposalOutcome:
        # The backend returns the existing grant for an action identifier it has already seen,
        # which is what makes a retried execution safe. A grant whose window has closed is the
        # one case where returning it would report a success that is not one, so the replay is
        # refused and a renewal has to be a new action with its own ticket and identifier.
        # Nothing here revokes or checks grants at use time; that remains unbuilt.
        existing = self._access.grant_for(action_id)
        if existing is not None and existing.expires_at is not None and now >= existing.expires_at:
            return _refused(
                GuardRefusalReason.EXPIRED_GRANT_REPLAY, resolved, action_id, digest, decision
            )

        # A grant always carries a duration; the dispatch above guarantees the operation, and the
        # resolved record's own validator guarantees the duration, so this cannot be None here.
        assert resolved.duration is not None
        self._record_executed(resolved, action_id, decision, now)
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
        return self._executed(resolved, action_id, digest, decision, now, approval_id, grant=grant)

    # Revoke and modify. The authoritative current-access preconditions and the destructive ledger
    # live in the backend, so each of its refusals maps to a fail-closed guard refusal and no
    # outcome carries a change unless the backend confirmed one. Unlike a grant, the executed
    # event is written after the change is confirmed rather than before: a revoke or a modify
    # cannot be safely re-driven, so an event claiming execution must not precede an outcome the
    # backend may refuse as uncertain (S10 decision 9; see DESIGN.md AD-46).
    def _execute_destructive(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
        approval_id: ApprovalId | None,
    ) -> ProposalOutcome:
        receipt = DestructiveReceipt(
            action_id=action_id,
            operation=resolved.operation,
            requester_id=resolved.requester_id,
            resource_id=resolved.resource_id,
            permission=resolved.permission,
            authorised_at=now,
        )
        apply = (
            self._access.revoke
            if resolved.operation is ProtectedOperation.REVOKE_ACCESS
            else self._access.modify
        )
        try:
            change = apply(receipt, self._minting_key)
        except CurrentAccessMismatchError:
            return _refused(
                GuardRefusalReason.CURRENT_ACCESS_MISMATCH, resolved, action_id, digest, decision
            )
        except NoCurrentAccessError:
            return _refused(
                GuardRefusalReason.NO_CURRENT_ACCESS, resolved, action_id, digest, decision
            )
        except UncertainDestructiveReplayError:
            return _refused(
                GuardRefusalReason.UNCERTAIN_DESTRUCTIVE_REPLAY,
                resolved,
                action_id,
                digest,
                decision,
            )

        self._record_executed(resolved, action_id, decision, now)
        return self._executed(
            resolved, action_id, digest, decision, now, approval_id, access_change=change
        )

    # The one shape an executed outcome takes, built here so a grant and a destructive change do
    # not each spell out the full record and drift apart. Exactly one of grant and access_change
    # is supplied; the outcome's own validator checks that against the operation.
    def _executed(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        digest: ArgumentDigest,
        decision: PolicyDecision,
        now: datetime,
        approval_id: ApprovalId | None,
        *,
        grant: AccessGrant | None = None,
        access_change: AccessChange | None = None,
    ) -> ProposalOutcome:
        return ProposalOutcome(
            outcome=GuardOutcome.EXECUTED,
            refusal_reason=None,
            resolved=resolved,
            action_id=action_id,
            argument_digest=digest,
            decision=decision,
            approval_id=approval_id,
            grant=grant,
            access_change=access_change,
            authorised_at=now,
        )

    def _record_executed(
        self, resolved: ResolvedAction, action_id: ActionId, decision: PolicyDecision, now: datetime
    ) -> None:
        # A destructive execution records its trusted reversibility classification, so the trail
        # says whether the change it names can be undone. It is read from configuration, never
        # from anything a model supplied. A grant records no detail, as before.
        reversibility = self._reversibility.get(resolved.operation)
        detail = None if reversibility is None else reversibility.value
        self._audit.record(
            AuditEvent.build(
                event_type=AuditEventType.EXECUTED,
                occurred_at=now,
                actor_type=ActorType.RUNTIME,
                workflow_id=resolved.workflow_id,
                action_id=action_id,
                outcome=GuardOutcome.EXECUTED,
                decision=decision,
                detail=detail,
            )
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

    def _resource(self, action: ProtectedActionProposal) -> Resource:
        try:
            return self._catalog.get(action.resource_id)
        except AegisDeskError:
            raise _Refused(GuardRefusalReason.UNRESOLVED_RESOURCE) from None

    def _baseline(self, session: EmployeeSessionContext, resource: Resource) -> Permission | None:
        return self._directory.get_baseline_permission(
            session.employee_id, session.employee_id, resource.resource_id
        )

    # Grant risk is keyed on the class, the permission and the duration; a revoke or a modify has
    # no duration, so its tier is keyed on the operation, the class and the permission from the
    # separate corpus. An unclassified triple fails closed either way (S10 decision 5).
    def _risk_tier(self, resource: Resource, action: ProtectedActionProposal) -> RiskTier:
        if isinstance(action, ProposedAction):
            tier = self._risk_tiers.get(
                (resource.resource_class, action.permission, action.duration)
            )
        else:
            tier = self._operation_risk_tiers.get(
                (action.operation, resource.resource_class, action.permission)
            )
        if tier is None:
            raise _Refused(GuardRefusalReason.UNCLASSIFIED_RISK)
        return tier
