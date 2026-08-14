import pytest

from aegisdesk.domain.enums import (
    DURATION_MAX_HOURS,
    PERMISSION_RANK,
    RISK_RANK,
    AccessDuration,
    AgentName,
    ApprovalRefusalReason,
    ApprovalStatus,
    AuditEventType,
    Capability,
    GuardOutcome,
    GuardRefusalReason,
    Permission,
    PolicyEffect,
    ProtectedOperation,
    RiskTier,
)

SECURITY_ENUMS = [
    AgentName,
    Permission,
    Capability,
    ProtectedOperation,
    PolicyEffect,
    ApprovalStatus,
    RiskTier,
    AccessDuration,
]


@pytest.mark.parametrize("value", ["superadmin", "ADMIN", "admin ", "*", ""])
def test_permission_rejects_free_form_values(value: str) -> None:
    with pytest.raises(ValueError):
        Permission(value)


@pytest.mark.parametrize("enum_type", SECURITY_ENUMS)
def test_security_enums_are_not_string_subclasses(enum_type: type) -> None:
    # A str-backed member compares equal to a bare string, which would let raw strings from
    # model output or checkpoint deserialisation satisfy a check that expects an enum.
    assert not issubclass(enum_type, str)


def test_security_enums_do_not_compare_equal_to_their_raw_values() -> None:
    # Typed as object because that is how such a value actually arrives: decoded JSON from
    # model output or a checkpoint, where the static type is unknown and only the runtime
    # comparison stands between a raw string and a security decision.
    raw_permission: object = "admin"
    raw_capability: object = "access.propose_grant"
    assert raw_permission != Permission.ADMIN
    assert raw_capability != Capability.ACCESS_PROPOSE_GRANT


def test_permission_rank_is_total_and_orders_admin_highest() -> None:
    assert set(PERMISSION_RANK) == set(Permission)
    assert (
        PERMISSION_RANK[Permission.READ]
        < PERMISSION_RANK[Permission.WRITE]
        < PERMISSION_RANK[Permission.ADMIN]
    )


def test_permission_rank_disagrees_with_alphabetical_ordering() -> None:
    # Guards the specific trap that motivates the rank table: sorting by value would put
    # admin first and make an "at most baseline" comparison approve every admin request.
    by_value = sorted(Permission, key=lambda p: p.value)
    by_rank = sorted(Permission, key=lambda p: PERMISSION_RANK[p])
    assert by_value != by_rank


def test_risk_rank_is_total_and_strictly_ordered() -> None:
    assert set(RISK_RANK) == set(RiskTier)
    ordered = (RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL)
    ranks = [RISK_RANK[tier] for tier in ordered]
    assert ranks == sorted(set(ranks))


def test_duration_hours_is_total_and_only_permanent_is_unbounded() -> None:
    assert set(DURATION_MAX_HOURS) == set(AccessDuration)
    unbounded = {d for d, hours in DURATION_MAX_HOURS.items() if hours is None}
    assert unbounded == {AccessDuration.PERMANENT}


def test_capability_and_protected_operation_are_disjoint() -> None:
    # A rename that merged the propose-side and execute-side vocabularies would make an
    # agent capability usable where an executable operation is expected.
    assert {c.value for c in Capability}.isdisjoint({op.value for op in ProtectedOperation})


def test_no_capability_denotes_execution_of_a_protected_operation() -> None:
    access_capabilities = {c for c in Capability if c.value.startswith("access.")}
    assert access_capabilities == {
        Capability.ACCESS_PROPOSE_GRANT,
        Capability.ACCESS_PROPOSE_REVOKE,
        Capability.ACCESS_PROPOSE_MODIFY,
    }
    assert all("propose" in c.value for c in access_capabilities)


def test_approved_is_not_the_first_approval_status_member() -> None:
    # Defends against any code taking a positional default from the enum.
    assert list(ApprovalStatus)[0] is ApprovalStatus.PENDING
    assert list(ApprovalStatus)[0] is not ApprovalStatus.APPROVED


def test_policy_effect_keeps_approval_distinct_from_allow_and_deny() -> None:
    assert len(PolicyEffect) == 3
    assert PolicyEffect.REQUIRE_APPROVAL not in (PolicyEffect.ALLOW, PolicyEffect.DENY)


def test_refused_is_the_first_guard_outcome_and_executed_the_last() -> None:
    # A positional default lands on the refusal, and neither of the other two can be reached by
    # an off-by-one from either end.
    assert list(GuardOutcome)[0] is GuardOutcome.REFUSED
    assert list(GuardOutcome)[-1] is GuardOutcome.EXECUTED
    assert GuardOutcome.AWAITING_APPROVAL not in (GuardOutcome.REFUSED, GuardOutcome.EXECUTED)


def test_a_pending_outcome_is_distinct_from_a_refusal() -> None:
    # A paused action is not a denied one, and the two are audited differently.
    assert len(GuardOutcome) == 3


def test_approval_refusal_reasons_are_distinct_from_guard_refusal_reasons() -> None:
    # Two boundaries, two vocabularies: a reviewer decision and a protected proposal fail for
    # different causes, and one enum covering both would let an audit line be read as either.
    assert {reason.value for reason in ApprovalRefusalReason}.isdisjoint(
        {reason.value for reason in GuardRefusalReason}
    )


def test_a_re_proposal_after_rejection_has_its_own_refusal_reason() -> None:
    # Distinct from a lapse and from the resume path's APPROVAL_NOT_GRANTED, so that an agent
    # re-proposing an action a human turned down is its own audit line.
    assert (
        len(
            {
                GuardRefusalReason.APPROVAL_ALREADY_REJECTED,
                GuardRefusalReason.APPROVAL_LAPSED,
                GuardRefusalReason.APPROVAL_NOT_GRANTED,
            }
        )
        == 3
    )


def test_audit_event_types_are_not_string_subclasses() -> None:
    # An audit type read back from a persisted trail or a checkpoint must not compare equal to a
    # raw string, for the same reason every other enum here is a plain Enum.
    assert not issubclass(AuditEventType, str)


def test_audit_event_types_cover_the_recorded_trajectory() -> None:
    assert {event.value for event in AuditEventType} == {
        "proposal_persisted",
        "awaiting_approval",
        "executed",
        "refused",
        "reviewer_decision",
        "cross_employee_ticket_attempt",
    }
