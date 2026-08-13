from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from aegisdesk.approval import (
    LEGAL_APPROVAL_TRANSITIONS,
    ApprovalDecision,
    ApprovalPolicy,
    ApprovalRecord,
    decision_tuple,
    effective_status,
    recorded_decision_tuple,
)
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

CREATED = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
DECIDED = CREATED + timedelta(hours=1)


def _fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "approval_id": ApprovalId("APR-0001"),
        "workflow_id": WorkflowId("WF-0001"),
        "action_id": ActionId("ACT-0001"),
        "ticket_id": TicketId("IT-0001"),
        "requester_id": EmployeeId("E1042"),
        "operation": ProtectedOperation.GRANT_ACCESS,
        "resource_id": ResourceId("prod-db"),
        "permission": Permission.ADMIN,
        "duration": AccessDuration.EIGHT_HOURS,
        "argument_digest": ArgumentDigest("a" * 64),
        "policy_version": PolicyVersion("1"),
        "effect": PolicyEffect.REQUIRE_APPROVAL,
        "reason": PolicyReason.PRIVILEGED_RESOURCE,
        "risk_tier": RiskTier.CRITICAL,
        "status": ApprovalStatus.PENDING,
        "created_at": CREATED,
        "pending_expires_at": CREATED + timedelta(hours=72),
        "reviewer_id": None,
        "decided_at": None,
        "approved_expires_at": None,
    }
    fields.update(overrides)
    return fields


def _approved(**overrides: Any) -> ApprovalRecord:
    return ApprovalRecord.model_validate(
        _fields(
            status=ApprovalStatus.APPROVED,
            reviewer_id=ReviewerId("E1055"),
            decided_at=DECIDED,
            approved_expires_at=DECIDED + timedelta(hours=4),
            **overrides,
        )
    )


# --- what a record may say about itself -------------------------------------------------------


def test_a_pending_record_names_no_reviewer_and_no_decision() -> None:
    record = ApprovalRecord.model_validate(_fields())
    assert record.status is ApprovalStatus.PENDING
    assert record.reviewer_id is None
    assert record.decided_at is None
    assert record.approved_expires_at is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"reviewer_id": ReviewerId("E1055")},
        {"decided_at": DECIDED},
        {"approved_expires_at": DECIDED + timedelta(hours=4)},
    ],
)
def test_a_pending_record_carrying_a_decision_is_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(_fields(**overrides))


def test_an_approved_record_without_a_reviewer_is_refused() -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(
            _fields(
                status=ApprovalStatus.APPROVED,
                decided_at=DECIDED,
                approved_expires_at=DECIDED + timedelta(hours=4),
            )
        )


def test_an_approved_record_without_an_expiry_is_refused() -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(
            _fields(
                status=ApprovalStatus.APPROVED,
                reviewer_id=ReviewerId("E1055"),
                decided_at=DECIDED,
            )
        )


def test_a_rejected_record_expires_nothing() -> None:
    record = ApprovalRecord.model_validate(
        _fields(
            status=ApprovalStatus.REJECTED,
            reviewer_id=ReviewerId("E1055"),
            decided_at=DECIDED,
        )
    )
    assert record.approved_expires_at is None
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(
            _fields(
                status=ApprovalStatus.REJECTED,
                reviewer_id=ReviewerId("E1055"),
                decided_at=DECIDED,
                approved_expires_at=DECIDED + timedelta(hours=4),
            )
        )


@pytest.mark.parametrize("effect", [PolicyEffect.ALLOW, PolicyEffect.DENY])
def test_only_a_require_approval_decision_may_be_recorded(effect: PolicyEffect) -> None:
    # A DENY reaching a reviewer would let a human approve what policy already refused, and an
    # ALLOW would create an approval nobody needed.
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(_fields(effect=effect))


@pytest.mark.parametrize("status", [ApprovalStatus.EXPIRED, ApprovalStatus.SUPERSEDED])
def test_a_derived_or_reserved_status_cannot_be_stored(status: ApprovalStatus) -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(_fields(status=status))


def test_a_pending_deadline_must_follow_creation() -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(_fields(pending_expires_at=CREATED))


def test_an_approved_deadline_must_follow_the_decision() -> None:
    with pytest.raises(ValidationError):
        ApprovalRecord.model_validate(
            _fields(
                status=ApprovalStatus.APPROVED,
                reviewer_id=ReviewerId("E1055"),
                decided_at=DECIDED,
                approved_expires_at=DECIDED,
            )
        )


def test_a_record_invariant_breach_is_a_domain_invariant_error() -> None:
    with pytest.raises(ValidationError) as excinfo:
        ApprovalRecord.model_validate(_fields(effect=PolicyEffect.DENY))
    causes = [error.get("ctx", {}).get("error") for error in excinfo.value.errors()]
    assert any(isinstance(cause, DomainInvariantError) for cause in causes)


def test_the_record_is_frozen_and_closed() -> None:
    record = ApprovalRecord.model_validate(_fields())
    with pytest.raises(ValueError):
        record.status = ApprovalStatus.APPROVED
    with pytest.raises(ValueError):
        ApprovalRecord.model_validate(_fields(reviewer_note="approved by phone"))


# --- the transition table ---------------------------------------------------------------------


def test_only_a_pending_record_has_anywhere_to_go() -> None:
    assert LEGAL_APPROVAL_TRANSITIONS[ApprovalStatus.PENDING] == frozenset(
        {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
    )
    for status in ApprovalStatus:
        if status is not ApprovalStatus.PENDING:
            assert LEGAL_APPROVAL_TRANSITIONS[status] == frozenset()


def test_every_status_appears_in_the_table() -> None:
    # A status missing from the permit-list would resolve to an empty set and deny, which is the
    # right failure, but an absent key is a gap nobody sees. Completeness is asserted instead.
    assert set(LEGAL_APPROVAL_TRANSITIONS) == set(ApprovalStatus)


def test_expiry_is_not_a_destination_anyone_may_write() -> None:
    assert all(
        ApprovalStatus.EXPIRED not in reachable for reachable in LEGAL_APPROVAL_TRANSITIONS.values()
    )


def test_superseded_has_no_producer() -> None:
    # Reserved, in the way PolicyReason.DEPARTMENT_MISMATCH is: a derived action identifier means
    # an amended action is a different action with its own record.
    assert all(
        ApprovalStatus.SUPERSEDED not in reachable
        for reachable in LEGAL_APPROVAL_TRANSITIONS.values()
    )


def test_reject_is_the_positional_default_decision() -> None:
    assert list(ApprovalDecision)[0] is ApprovalDecision.REJECT


# --- expiry is derived, not stored --------------------------------------------------------------


def test_a_pending_record_lapses_on_its_own_deadline() -> None:
    record = ApprovalRecord.model_validate(_fields())
    assert effective_status(record, record.pending_expires_at - timedelta(seconds=1)) is (
        ApprovalStatus.PENDING
    )
    assert effective_status(record, record.pending_expires_at) is ApprovalStatus.EXPIRED


def test_an_approved_record_lapses_on_its_own_deadline() -> None:
    record = _approved()
    assert record.approved_expires_at is not None
    assert effective_status(record, record.approved_expires_at - timedelta(seconds=1)) is (
        ApprovalStatus.APPROVED
    )
    assert effective_status(record, record.approved_expires_at) is ApprovalStatus.EXPIRED


def test_a_rejected_record_never_lapses_into_anything_else() -> None:
    record = ApprovalRecord.model_validate(
        _fields(
            status=ApprovalStatus.REJECTED,
            reviewer_id=ReviewerId("E1055"),
            decided_at=DECIDED,
        )
    )
    assert effective_status(record, DECIDED + timedelta(days=400)) is ApprovalStatus.REJECTED


def test_expiry_leaves_the_stored_record_untouched() -> None:
    record = _approved()
    effective_status(record, DECIDED + timedelta(days=1))
    assert record.status is ApprovalStatus.APPROVED


# --- the decision tuple -------------------------------------------------------------------------


def _decision(**overrides: Any) -> PolicyDecision:
    fields: dict[str, Any] = {
        "policy_version": PolicyVersion("1"),
        "effect": PolicyEffect.REQUIRE_APPROVAL,
        "reason": PolicyReason.PRIVILEGED_RESOURCE,
        "workflow_id": WorkflowId("WF-0001"),
        "action_id": ActionId("ACT-0001"),
        "evaluated_at": CREATED,
        "requester_id": EmployeeId("E1042"),
        "resource_id": ResourceId("prod-db"),
        "permission": Permission.ADMIN,
        "duration": AccessDuration.EIGHT_HOURS,
        "risk_tier": RiskTier.CRITICAL,
    }
    fields.update(overrides)
    return PolicyDecision.model_validate(fields)


def test_a_record_and_its_decision_produce_the_same_tuple() -> None:
    assert recorded_decision_tuple(_approved()) == decision_tuple(_decision())


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_version": PolicyVersion("2")},
        {"effect": PolicyEffect.DENY},
        {"reason": PolicyReason.STANDING_PRIVILEGED_ACCESS},
        {"requester_id": EmployeeId("E1043")},
        {"resource_id": ResourceId("payroll")},
        {"permission": Permission.READ},
        {"duration": AccessDuration.ONE_HOUR},
    ],
)
def test_changing_any_bound_value_changes_the_tuple(overrides: dict[str, Any]) -> None:
    assert decision_tuple(_decision(**overrides)) != recorded_decision_tuple(_approved())


def test_the_evaluation_timestamp_is_outside_the_tuple() -> None:
    # Whole decisions cannot be compared on resume: evaluated_at legitimately differs between
    # the proposing pass and the resuming one (DESIGN.md AD-34).
    later = _decision(evaluated_at=CREATED + timedelta(hours=2))
    assert later != _decision()
    assert decision_tuple(later) == decision_tuple(_decision())


def test_the_risk_tier_is_outside_the_tuple() -> None:
    # Recorded for the reviewer and the audit trail, consulted by nothing, so a tier that
    # changed underneath an approval does not invalidate it.
    assert decision_tuple(_decision(risk_tier=RiskTier.LOW)) == decision_tuple(_decision())


def test_an_unreadable_decision_has_no_comparable_tuple() -> None:
    unreadable = PolicyDecision.model_validate(
        {
            "policy_version": PolicyVersion("1"),
            "effect": PolicyEffect.DENY,
            "reason": PolicyReason.EVALUATION_ERROR,
            "workflow_id": None,
            "action_id": None,
            "evaluated_at": None,
            "requester_id": None,
            "resource_id": None,
            "permission": None,
            "duration": None,
            "risk_tier": None,
        }
    )
    with pytest.raises(DomainInvariantError):
        decision_tuple(unreadable)


# --- the time-box corpus ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"pending_ttl_hours": 0, "approved_ttl_hours": 4},
        {"pending_ttl_hours": 72, "approved_ttl_hours": 0},
        {"pending_ttl_hours": -1, "approved_ttl_hours": 4},
    ],
)
def test_a_non_positive_time_box_is_refused(fields: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        ApprovalPolicy.model_validate(fields)


def test_the_time_box_record_is_closed() -> None:
    with pytest.raises(ValueError):
        ApprovalPolicy.model_validate(
            {"pending_ttl_hours": 72, "approved_ttl_hours": 4, "grace_hours": 24}
        )
