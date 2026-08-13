import contextlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from aegisdesk.action import ResolvedAction
from aegisdesk.approval import (
    LEGAL_APPROVAL_TRANSITIONS,
    ApprovalDecision,
    ApprovalPolicy,
    ApprovalRecord,
    effective_status,
)
from aegisdesk.audit import AuditEvent
from aegisdesk.backends.audit import AuditSink
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.domain.enums import ActorType, ApprovalRefusalReason, ApprovalStatus, AuditEventType
from aegisdesk.domain.errors import (
    AegisDeskError,
    ApprovalCapacityError,
    ApprovalDecisionError,
    DomainInvariantError,
)
from aegisdesk.domain.ids import (
    ActionId,
    ApprovalId,
    ArgumentDigest,
    EmployeeId,
    ReviewerId,
    WorkflowId,
)
from aegisdesk.policy import PolicyDecision
from aegisdesk.session import ReviewerSessionContext

# A containment limit rather than a company policy value: project.md 13.6 lists maximum handoff
# and tool-call counts among the runtime controls, and this is the same kind of bound. It exists
# so that an agent cannot manufacture reviewer fatigue by varying one field of an action until a
# queue is full of near-identical requests.
MAX_PENDING_APPROVALS_PER_WORKFLOW: Final = 5


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalStore(Protocol):
    def open(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        argument_digest: ArgumentDigest,
        decision: PolicyDecision,
    ) -> ApprovalRecord: ...

    def get(self, workflow_id: WorkflowId, action_id: ActionId) -> ApprovalRecord | None: ...

    def decide(
        self,
        reviewer: ReviewerSessionContext,
        approval_id: ApprovalId,
        decision: ApprovalDecision,
    ) -> ApprovalRecord: ...

    def reviewer_is_eligible(self, reviewer_id: ReviewerId, requester_id: EmployeeId) -> bool: ...


class InMemoryApprovalStore(ApprovalStore):
    def __init__(
        self,
        directory: DirectoryBackend,
        reviewers: frozenset[ReviewerId],
        policy: ApprovalPolicy,
        audit: AuditSink,
        clock: Callable[[], datetime] = _utc_now,
        max_pending_per_workflow: int = MAX_PENDING_APPROVALS_PER_WORKFLOW,
    ) -> None:
        self._directory = directory
        self._reviewers = reviewers
        self._policy = policy
        self._audit = audit
        self._clock = clock
        self._max_pending = max_pending_per_workflow
        self._records: dict[tuple[WorkflowId, ActionId], ApprovalRecord] = {}
        self._by_approval_id: dict[ApprovalId, tuple[WorkflowId, ActionId]] = {}

    # Insert-if-absent under the derived key. Everything before a workflow pause runs again when
    # the workflow resumes (NON_NEGOTIABLES 6), so a second call for the same action returns the
    # record the first one wrote: same identifier, same created_at, same status. That is what
    # keeps a replay from resetting a rejection or notifying a reviewer twice.
    def open(
        self,
        resolved: ResolvedAction,
        action_id: ActionId,
        argument_digest: ArgumentDigest,
        decision: PolicyDecision,
    ) -> ApprovalRecord:
        key = (resolved.workflow_id, action_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        # Only a readable decision reaches here, and PolicyDecision's validator guarantees the
        # tier is present for one, so this cannot fire through any reachable path. It exists
        # because the field is Optional and a record must not be opened around a None.
        if decision.risk_tier is None:
            raise DomainInvariantError("an unreadable decision cannot open an approval record")
        self._require_capacity(resolved.workflow_id)

        created_at = self._clock()
        record = ApprovalRecord(
            approval_id=_derive_approval_id(action_id),
            workflow_id=resolved.workflow_id,
            action_id=action_id,
            ticket_id=resolved.ticket_id,
            requester_id=resolved.requester_id,
            operation=resolved.operation,
            resource_id=resolved.resource_id,
            permission=resolved.permission,
            duration=resolved.duration,
            argument_digest=argument_digest,
            policy_version=decision.policy_version,
            effect=decision.effect,
            reason=decision.reason,
            risk_tier=decision.risk_tier,
            status=ApprovalStatus.PENDING,
            created_at=created_at,
            pending_expires_at=created_at + timedelta(hours=self._policy.pending_ttl_hours),
            reviewer_id=None,
            decided_at=None,
            approved_expires_at=None,
        )
        self._records[key] = record
        self._by_approval_id[record.approval_id] = key
        return record

    def get(self, workflow_id: WorkflowId, action_id: ActionId) -> ApprovalRecord | None:
        return self._records.get((workflow_id, action_id))

    # The reviewer decides against an approval identifier, which is safe here and only here:
    # this caller is authenticated as a reviewer, and the record names the action it belongs to.
    # The resume path never accepts one (DESIGN.md AD-34).
    def decide(
        self,
        reviewer: ReviewerSessionContext,
        approval_id: ApprovalId,
        decision: ApprovalDecision,
    ) -> ApprovalRecord:
        # The annotation is a promise, not a check. An object merely carrying a reviewer_id
        # would otherwise reach the roster comparison, which is the claim reviewer
        # authentication exists to refuse.
        if not isinstance(reviewer, ReviewerSessionContext):
            raise ApprovalDecisionError(ApprovalRefusalReason.UNTRUSTED_REVIEWER_SESSION)
        if not isinstance(decision, ApprovalDecision):
            raise ApprovalDecisionError(ApprovalRefusalReason.MALFORMED_DECISION)
        # Roster and liveness first, so a caller who may decide nothing learns nothing about
        # which approval identifiers are real by watching what happens next.
        self._require_rostered(reviewer.reviewer_id)
        self._require_active(reviewer.reviewer_id)

        key = self._by_approval_id.get(approval_id)
        record = None if key is None else self._records.get(key)
        if record is None:
            raise ApprovalDecisionError(ApprovalRefusalReason.UNKNOWN_APPROVAL)
        _require_not_self_approval(reviewer.reviewer_id, record.requester_id)

        target = (
            ApprovalStatus.APPROVED
            if decision is ApprovalDecision.APPROVE
            else ApprovalStatus.REJECTED
        )
        # The permit-list is also the decided-once check and the expiry check: only PENDING has
        # a non-empty destination set, and a lapsed record reads as EXPIRED, which has none.
        current = effective_status(record, self._clock())
        if target not in LEGAL_APPROVAL_TRANSITIONS.get(current, frozenset()):
            raise ApprovalDecisionError(ApprovalRefusalReason.ILLEGAL_TRANSITION)

        stored = self._decided(record, reviewer.reviewer_id, target)
        self._records[record.workflow_id, record.action_id] = stored
        self._record_reviewer_decision(stored, target)
        return stored

    # A reviewer's decision is part of the security-relevant approval trajectory, so it is
    # recorded on the append-only trail. Best-effort: the decision is already durable in the
    # record above, and a failure of the recording boundary must not undo a decision a reviewer
    # made. The entry is keyed on (workflow, action), and a decided record is terminal, so it is
    # written once.
    def _record_reviewer_decision(self, record: ApprovalRecord, target: ApprovalStatus) -> None:
        with contextlib.suppress(Exception):
            self._audit.record(
                AuditEvent.build(
                    event_type=AuditEventType.REVIEWER_DECISION,
                    occurred_at=self._clock(),
                    actor_type=ActorType.REVIEWER,
                    actor_id=record.reviewer_id,
                    workflow_id=record.workflow_id,
                    action_id=record.action_id,
                    detail=target.value,
                )
            )

    def _decided(
        self, record: ApprovalRecord, reviewer_id: ReviewerId, target: ApprovalStatus
    ) -> ApprovalRecord:
        decided_at = self._clock()
        expires_at = (
            decided_at + timedelta(hours=self._policy.approved_ttl_hours)
            if target is ApprovalStatus.APPROVED
            else None
        )
        decided = record.model_copy(
            update={
                "status": target,
                "reviewer_id": reviewer_id,
                "decided_at": decided_at,
                "approved_expires_at": expires_at,
            }
        )
        # model_copy skips validation, so the copy goes back through the record's invariants
        # rather than being trusted for having come from a valid one.
        return ApprovalRecord.model_validate(decided.model_dump())

    # Re-checked by the resume path, because a reviewer can be offboarded or taken off the
    # roster between deciding and the workflow resuming.
    def reviewer_is_eligible(self, reviewer_id: ReviewerId, requester_id: EmployeeId) -> bool:
        try:
            self._require_rostered(reviewer_id)
            self._require_active(reviewer_id)
            _require_not_self_approval(reviewer_id, requester_id)
        except ApprovalDecisionError:
            return False
        return True

    def _require_capacity(self, workflow_id: WorkflowId) -> None:
        at = self._clock()
        pending = sum(
            1
            for (existing_workflow, _), record in self._records.items()
            if existing_workflow == workflow_id
            and effective_status(record, at) is ApprovalStatus.PENDING
        )
        if pending >= self._max_pending:
            raise ApprovalCapacityError("the workflow already holds its maximum pending approvals")

    # Exact comparison. The roster is a set of identifiers the directory issued, and a lookup
    # that folded case would let two spellings name one reviewer.
    def _require_rostered(self, reviewer_id: ReviewerId) -> None:
        if reviewer_id not in self._reviewers:
            raise ApprovalDecisionError(ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER)

    def _require_active(self, reviewer_id: ReviewerId) -> None:
        employee_id = EmployeeId(reviewer_id)
        try:
            employee = self._directory.get_employee(employee_id, employee_id)
        except AegisDeskError:
            raise ApprovalDecisionError(ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER) from None
        if not employee.is_active:
            raise ApprovalDecisionError(ApprovalRefusalReason.REVIEWER_INACTIVE)


# Compared case-insensitively, which is stricter than the exact matching used everywhere else
# and deliberately so: the two comparisons answer different questions. Roster membership asks
# whether this identifier was issued, so it must be exact. Self-approval asks whether these two
# identifiers name the same person, so a spelling that differs only in case must still count as
# the same person rather than as a way past the rule.
def _require_not_self_approval(reviewer_id: ReviewerId, requester_id: EmployeeId) -> None:
    if reviewer_id.casefold() == requester_id.casefold():
        raise ApprovalDecisionError(ApprovalRefusalReason.SELF_APPROVAL)


# Derived from the action identifier, which is itself derived, so the value is stable across the
# replay of a pre-pause pass without anything persisting a random number. It is not a secret and
# is not treated as one: the resume path looks records up by (workflow_id, action_id) and has no
# field an approval identifier could arrive in.
def _derive_approval_id(action_id: ActionId) -> ApprovalId:
    return ApprovalId(f"APR-{action_id.removeprefix('ACT-')}")
