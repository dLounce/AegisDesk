from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Final, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.domain.enums import (
    AccessDuration,
    ApprovalStatus,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    RiskTier,
)
from aegisdesk.domain.errors import DomainInvariantError
from aegisdesk.domain.ids import (
    ActionId,
    ApprovalId,
    ArgumentDigest,
    EmployeeId,
    PolicyVersion,
    ResourceId,
    ReviewerId,
    TicketId,
    WorkflowId,
)
from aegisdesk.policy import PolicyDecision


# REJECT is first, so code reaching for a positional default lands on the decision that grants
# nothing. There is no "abstain": a reviewer who does not decide leaves the record pending, and
# the pending time-box handles it without anybody writing a status.
class ApprovalDecision(Enum):
    REJECT = "reject"
    APPROVE = "approve"


# The only transitions a reviewer may cause, declared as a permit-list for the same reason
# LEGAL_TICKET_TRANSITIONS is. Every status other than PENDING is terminal, so a decided record
# cannot be decided again and a second reviewer cannot overturn the first.
#
# EXPIRED is absent as a destination because expiry is not a decision: it is derived from the
# record's own deadlines by effective_status below, so no clock-dependent write exists to
# replay, and a store outage cannot leave a record un-expired. SUPERSEDED is absent because
# nothing produces it — a derived action_id means an amended action is a different action with
# its own record — and it stays reserved until a replacement workflow needs it.
LEGAL_APPROVAL_TRANSITIONS: Final[Mapping[ApprovalStatus, frozenset[ApprovalStatus]]] = {
    ApprovalStatus.PENDING: frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}),
    ApprovalStatus.APPROVED: frozenset(),
    ApprovalStatus.REJECTED: frozenset(),
    ApprovalStatus.EXPIRED: frozenset(),
    ApprovalStatus.SUPERSEDED: frozenset(),
}

# What a resume compares. The evaluation timestamp is deliberately outside it: it differs
# legitimately between the proposing pass and the resuming one, so whole decisions cannot be
# compared (DESIGN.md AD-34).
DecisionTuple = tuple[
    PolicyVersion,
    PolicyEffect,
    PolicyReason,
    EmployeeId,
    ResourceId | None,
    Permission,
    AccessDuration | None,
]


# The authoritative answer to "was this exact action authorised, by whom, and until when".
# Every field is resolved by the runtime guard before the record is opened; nothing a model
# wrote reaches it. The record is written once when the action is proposed and once more when
# a reviewer decides, and never again.
class ApprovalRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: ApprovalId
    # The lookup key on resume is (workflow_id, action_id), both derived by the resuming pass.
    # approval_id names the record for a reviewer's screen and is never a resume credential.
    workflow_id: WorkflowId
    action_id: ActionId
    ticket_id: TicketId

    requester_id: EmployeeId
    operation: ProtectedOperation
    resource_id: ResourceId
    permission: Permission
    # Present for a grant, absent for a revoke or a modify, which have no duration to record.
    duration: AccessDuration | None

    argument_digest: ArgumentDigest
    policy_version: PolicyVersion
    effect: PolicyEffect
    reason: PolicyReason
    risk_tier: RiskTier

    status: ApprovalStatus
    created_at: AwareDatetime
    pending_expires_at: AwareDatetime

    reviewer_id: ReviewerId | None
    decided_at: AwareDatetime | None
    approved_expires_at: AwareDatetime | None

    @model_validator(mode="after")
    def _record_agrees_with_status(self) -> Self:
        # A record exists because policy required a human. Storing an ALLOW would create an
        # approval nobody asked for; storing a DENY would put a refused action in front of a
        # reviewer who could approve what policy already refused (DESIGN.md AD-22).
        if self.effect is not PolicyEffect.REQUIRE_APPROVAL:
            raise DomainInvariantError("an approval record must carry a REQUIRE_APPROVAL decision")
        is_grant = self.operation is ProtectedOperation.GRANT_ACCESS
        if is_grant and self.duration is None:
            raise DomainInvariantError("a grant record must carry a duration")
        if not is_grant and self.duration is not None:
            raise DomainInvariantError(f"a {self.operation.value} record must not carry a duration")
        if self.pending_expires_at <= self.created_at:
            raise DomainInvariantError("pending_expires_at must be later than created_at")

        decided = (self.reviewer_id, self.decided_at)
        if self.status is ApprovalStatus.PENDING:
            if any(field is not None for field in (*decided, self.approved_expires_at)):
                raise DomainInvariantError("a pending record must name no reviewer and no decision")
        elif self.status is ApprovalStatus.REJECTED:
            if any(field is None for field in decided) or self.approved_expires_at is not None:
                raise DomainInvariantError("a rejected record must name a reviewer and no expiry")
        elif self.status is ApprovalStatus.APPROVED:
            if any(field is None for field in decided) or self.approved_expires_at is None:
                raise DomainInvariantError("an approved record must name its reviewer and expiry")
            if self.decided_at is not None and self.approved_expires_at <= self.decided_at:
                raise DomainInvariantError("approved_expires_at must be later than decided_at")
        else:
            # EXPIRED is derived rather than stored, and SUPERSEDED has no producer. Refusing
            # them here means a store that learns to write one has to come back through this
            # validator rather than slipping a status past the transition table.
            raise DomainInvariantError(f"{self.status.value} is not a storable approval status")
        return self


# Expiry is read from the record rather than written to it, so the answer does not depend on
# whether a sweep ran, and a replayed resume cannot find a record a crash left un-expired.
def effective_status(record: ApprovalRecord, at: datetime) -> ApprovalStatus:
    if record.status is ApprovalStatus.PENDING and at >= record.pending_expires_at:
        return ApprovalStatus.EXPIRED
    if (
        record.status is ApprovalStatus.APPROVED
        and record.approved_expires_at is not None
        and at >= record.approved_expires_at
    ):
        return ApprovalStatus.EXPIRED
    return record.status


def decision_tuple(decision: PolicyDecision) -> DecisionTuple:
    # Only a readable decision reaches an approval record, and PolicyDecision's own validator
    # guarantees these fields are present for one, so the assertions below cannot fire through
    # any reachable path. They exist because the type is Optional and mypy is strict. duration is
    # deliberately not asserted: a readable revoke or modify decision carries none.
    if decision.requester_id is None or decision.permission is None:
        raise DomainInvariantError("an unreadable decision has no comparable tuple")
    return (
        decision.policy_version,
        decision.effect,
        decision.reason,
        decision.requester_id,
        decision.resource_id,
        decision.permission,
        decision.duration,
    )


def recorded_decision_tuple(record: ApprovalRecord) -> DecisionTuple:
    return (
        record.policy_version,
        record.effect,
        record.reason,
        record.requester_id,
        record.resource_id,
        record.permission,
        record.duration,
    )


# Reference configuration for the fictional company, in the way the risk-tier corpus is.
# project.md states no approval time-box anywhere, so the values live in seed data and this
# module holds only their shape.
class ApprovalPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # How long a reviewer has to decide before the record lapses on its own.
    pending_ttl_hours: int
    # How long an approval stays executable after it is granted. Short by design: the gap
    # between authorising an action and performing it is the window in which the world can
    # change underneath a decision a human already made.
    approved_ttl_hours: int

    @model_validator(mode="after")
    def _time_boxes_are_positive(self) -> Self:
        if self.pending_ttl_hours <= 0 or self.approved_ttl_hours <= 0:
            raise DomainInvariantError("approval time-boxes must be positive")
        return self
