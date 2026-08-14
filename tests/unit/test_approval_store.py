from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegisdesk.action import ResolvedAction, compute_argument_digest, derive_action_id
from aegisdesk.approval import ApprovalDecision, ApprovalPolicy
from aegisdesk.audit import AuditEvent
from aegisdesk.backends.approvals import InMemoryApprovalStore
from aegisdesk.backends.audit import InMemoryAuditSink
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import load_baseline_access, load_employees
from aegisdesk.domain.enums import (
    AccessDuration,
    ActorType,
    ApprovalRefusalReason,
    ApprovalStatus,
    AuditEventType,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    RiskTier,
)
from aegisdesk.domain.errors import ApprovalCapacityError, ApprovalDecisionError
from aegisdesk.domain.ids import (
    ApprovalId,
    EmployeeId,
    PolicyVersion,
    ResourceId,
    ReviewerId,
    TicketId,
    WorkflowId,
)
from aegisdesk.policy import POLICY_VERSION, PolicyDecision
from aegisdesk.session import EmployeeSessionContext, ReviewerSessionContext

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WORKFLOW = WorkflowId("WF-0001")

REQUESTER = EmployeeId("E1042")
REVIEWER = ReviewerId("E1055")
OFF_ROSTER = ReviewerId("E1043")
INACTIVE = ReviewerId("E9099")

POLICY = ApprovalPolicy(pending_ttl_hours=72, approved_ttl_hours=4)


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


def _resolved(**overrides: Any) -> ResolvedAction:
    fields: dict[str, Any] = {
        "operation": ProtectedOperation.GRANT_ACCESS,
        "requester_id": REQUESTER,
        "resource_id": ResourceId("prod-db"),
        "permission": Permission.ADMIN,
        "duration": AccessDuration.EIGHT_HOURS,
        "ticket_id": TicketId("IT-0001"),
        "workflow_id": WORKFLOW,
    }
    fields.update(overrides)
    return ResolvedAction.model_validate(fields)


def _decision(resolved: ResolvedAction, **overrides: Any) -> PolicyDecision:
    action_id = derive_action_id(resolved)
    fields: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "effect": PolicyEffect.REQUIRE_APPROVAL,
        "reason": PolicyReason.PRIVILEGED_RESOURCE,
        "operation": resolved.operation,
        "workflow_id": resolved.workflow_id,
        "action_id": action_id,
        "evaluated_at": AT,
        "requester_id": resolved.requester_id,
        "resource_id": resolved.resource_id,
        "permission": resolved.permission,
        "duration": resolved.duration,
        "risk_tier": RiskTier.CRITICAL,
    }
    fields.update(overrides)
    return PolicyDecision.model_validate(fields)


# The roster is fixed at construction in production. This subclass makes it movable so that a
# reviewer taken off the roster after deciding can be exercised, which is the offboarding case
# the resume path re-checks for.
class MutableRosterStore(InMemoryApprovalStore):
    def __init__(
        self,
        directory: DirectoryBackend,
        reviewers: frozenset[ReviewerId],
        policy: ApprovalPolicy,
        audit: InMemoryAuditSink,
        clock: Clock,
        max_pending_per_workflow: int = 5,
    ) -> None:
        super().__init__(directory, reviewers, policy, audit, clock, max_pending_per_workflow)
        self.roster = set(reviewers)

    def _require_rostered(self, reviewer_id: ReviewerId) -> None:
        if reviewer_id not in self.roster:
            raise ApprovalDecisionError(ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER)


class Fixture:
    def __init__(self, max_pending: int = 5) -> None:
        self.clock = Clock(AT)
        self.audit = InMemoryAuditSink()
        self.directory = DirectoryBackend(load_employees(), load_baseline_access())
        self.store = MutableRosterStore(
            self.directory,
            frozenset({REVIEWER, INACTIVE}),
            POLICY,
            self.audit,
            self.clock,
            max_pending,
        )
        self.reviewer = ReviewerSessionContext(reviewer_id=REVIEWER, authenticated_at=AT)

    # Untrusted-shaped arguments reach the store through here, in the way the guard fixture
    # passes a session it does not vouch for.
    def decide(self, reviewer: Any, approval_id: Any, decision: Any) -> Any:
        return self.store.decide(reviewer, approval_id, decision)

    def open(self, **overrides: Any) -> Any:
        resolved = _resolved(**overrides)
        action_id = derive_action_id(resolved)
        digest = compute_argument_digest(resolved, action_id, POLICY_VERSION)
        return self.store.open(resolved, action_id, digest, _decision(resolved))


@pytest.fixture
def fixture() -> Fixture:
    return Fixture()


# --- opening a record is idempotent under replay -----------------------------------------------


def test_a_record_opens_pending_with_its_own_deadline(fixture: Fixture) -> None:
    record = fixture.open()
    assert record.status is ApprovalStatus.PENDING
    assert record.created_at == AT
    assert record.pending_expires_at == AT + timedelta(hours=72)
    assert record.reviewer_id is None


def test_repeating_the_pre_pause_pass_writes_one_record(fixture: Fixture) -> None:
    # Whatever runs before a pause runs again on resume, so a second open must return the record
    # the first one wrote rather than a fresh one with a fresh deadline.
    first = fixture.open()
    fixture.clock.at = AT + timedelta(hours=5)
    second = fixture.open()
    third = fixture.open()
    assert first == second == third
    assert second.created_at == AT
    assert fixture.store.get(WORKFLOW, first.action_id) == first


def test_a_replayed_open_does_not_reset_a_decision(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.REJECT)
    replayed = fixture.open()
    assert replayed.status is ApprovalStatus.REJECTED
    assert replayed.reviewer_id == REVIEWER


def test_the_approval_identifier_is_derived_from_the_action(fixture: Fixture) -> None:
    record = fixture.open()
    assert record.approval_id == ApprovalId(f"APR-{record.action_id.removeprefix('ACT-')}")


def test_distinct_actions_open_distinct_records(fixture: Fixture) -> None:
    first = fixture.open()
    second = fixture.open(duration=AccessDuration.ONE_HOUR)
    assert first.action_id != second.action_id
    assert first.approval_id != second.approval_id


def test_a_record_carries_the_resolved_action_rather_than_a_proposal(fixture: Fixture) -> None:
    record = fixture.open()
    assert record.requester_id == REQUESTER
    assert record.resource_id == ResourceId("prod-db")
    assert record.ticket_id == TicketId("IT-0001")
    assert record.workflow_id == WORKFLOW
    assert record.policy_version == POLICY_VERSION


# --- the pending cap ----------------------------------------------------------------------------


def test_a_workflow_may_not_queue_more_pending_approvals_than_its_cap() -> None:
    fixture = Fixture(max_pending=2)
    fixture.open(duration=AccessDuration.ONE_HOUR)
    fixture.open(duration=AccessDuration.EIGHT_HOURS)
    with pytest.raises(ApprovalCapacityError):
        fixture.open(duration=AccessDuration.PERMANENT)


def test_the_cap_counts_only_pending_records() -> None:
    fixture = Fixture(max_pending=1)
    first = fixture.open(duration=AccessDuration.ONE_HOUR)
    fixture.store.decide(fixture.reviewer, first.approval_id, ApprovalDecision.REJECT)
    # A decided record no longer occupies the queue a reviewer has to read.
    assert fixture.open(duration=AccessDuration.EIGHT_HOURS) is not None


def test_the_cap_releases_when_a_record_lapses() -> None:
    fixture = Fixture(max_pending=1)
    fixture.open(duration=AccessDuration.ONE_HOUR)
    fixture.clock.at = AT + timedelta(hours=73)
    assert fixture.open(duration=AccessDuration.EIGHT_HOURS) is not None


def test_a_replayed_open_is_not_counted_against_the_cap() -> None:
    fixture = Fixture(max_pending=1)
    fixture.open()
    assert fixture.open() is not None


# --- who may decide -----------------------------------------------------------------------------


def test_a_rostered_active_reviewer_may_approve(fixture: Fixture) -> None:
    record = fixture.open()
    decided = fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE)
    assert decided.status is ApprovalStatus.APPROVED
    assert decided.reviewer_id == REVIEWER
    assert decided.decided_at == AT
    assert decided.approved_expires_at == AT + timedelta(hours=4)


def test_a_decision_is_stored_rather_than_only_returned(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE)
    stored = fixture.store.get(WORKFLOW, record.action_id)
    assert stored is not None
    assert stored.status is ApprovalStatus.APPROVED


@pytest.mark.parametrize(
    "reviewer",
    [
        None,
        "E1055",
        {"reviewer_id": "E1055"},
        EmployeeSessionContext(employee_id=EmployeeId("E1055"), authenticated_at=AT),
    ],
)
def test_anything_that_is_not_a_reviewer_session_is_refused(
    reviewer: Any, fixture: Fixture
) -> None:
    record = fixture.open()
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.decide(reviewer, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.UNTRUSTED_REVIEWER_SESSION
    assert fixture.store.get(WORKFLOW, record.action_id) == record


class LookalikeReviewer:
    """Carries a reviewer_id and nothing else that makes it a session."""

    def __init__(self, reviewer_id: str) -> None:
        self.reviewer_id = ReviewerId(reviewer_id)
        self.authenticated_at = AT


def test_a_lookalike_reviewer_object_is_refused(fixture: Fixture) -> None:
    record = fixture.open()
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.decide(LookalikeReviewer(REVIEWER), record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.UNTRUSTED_REVIEWER_SESSION


@pytest.mark.parametrize("decision", [None, "approve", 1])
def test_anything_that_is_not_a_decision_is_refused(decision: Any, fixture: Fixture) -> None:
    record = fixture.open()
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.decide(fixture.reviewer, record.approval_id, decision)
    assert excinfo.value.reason is ApprovalRefusalReason.MALFORMED_DECISION


def test_a_reviewer_off_the_roster_is_refused(fixture: Fixture) -> None:
    record = fixture.open()
    session = ReviewerSessionContext(reviewer_id=OFF_ROSTER, authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER


def test_an_inactive_reviewer_is_refused(fixture: Fixture) -> None:
    # On the roster, so this is the offboarding case rather than an unknown reviewer.
    record = fixture.open()
    session = ReviewerSessionContext(reviewer_id=INACTIVE, authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.REVIEWER_INACTIVE


def test_the_roster_check_precedes_the_record_lookup(fixture: Fixture) -> None:
    # A caller who may decide nothing learns nothing about which approval identifiers are real.
    session = ReviewerSessionContext(reviewer_id=OFF_ROSTER, authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, ApprovalId("APR-nothing"), ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER


def test_an_unknown_approval_identifier_is_refused(fixture: Fixture) -> None:
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(fixture.reviewer, ApprovalId("APR-nothing"), ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.UNKNOWN_APPROVAL


# --- self-approval ------------------------------------------------------------------------------


def test_a_requester_may_not_decide_their_own_action(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.store.roster.add(ReviewerId(REQUESTER))
    session = ReviewerSessionContext(reviewer_id=ReviewerId(REQUESTER), authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.SELF_APPROVAL


def test_self_approval_is_refused_when_two_spellings_resolve_to_one_person() -> None:
    # Roster membership asks whether an identifier was issued and stays exact. Self-approval asks
    # whether two identifiers name the same person, so a spelling that differs only in case must
    # still count as the same person.
    #
    # Today the directory would refuse the second spelling before the rule is reached, and
    # authenticate_reviewer would refuse it earlier still. This fixture gives the directory both
    # spellings, which is the drift the rule exists to survive: the moment anything resolves
    # identifiers case-insensitively, this comparison is the control that holds.
    employees = dict(load_employees())
    twin = employees[REQUESTER].model_copy(update={"employee_id": EmployeeId("e1042")})
    employees[EmployeeId("e1042")] = twin

    fixture = Fixture()
    fixture.directory = DirectoryBackend(employees, load_baseline_access())
    fixture.store = MutableRosterStore(
        fixture.directory, frozenset({ReviewerId("e1042")}), POLICY, fixture.audit, fixture.clock
    )
    record = fixture.open()
    session = ReviewerSessionContext(reviewer_id=ReviewerId("e1042"), authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.SELF_APPROVAL
    assert fixture.store.reviewer_is_eligible(ReviewerId("e1042"), REQUESTER) is False


def test_the_roster_itself_is_matched_exactly(fixture: Fixture) -> None:
    record = fixture.open()
    session = ReviewerSessionContext(reviewer_id=ReviewerId("e1055"), authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(session, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.REVIEWER_NOT_ON_ROSTER


# --- decide once --------------------------------------------------------------------------------


@pytest.mark.parametrize("first", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
@pytest.mark.parametrize("second", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
def test_a_decided_record_cannot_be_decided_again(
    first: ApprovalDecision, second: ApprovalDecision, fixture: Fixture
) -> None:
    record = fixture.open()
    decided = fixture.store.decide(fixture.reviewer, record.approval_id, first)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(fixture.reviewer, record.approval_id, second)
    assert excinfo.value.reason is ApprovalRefusalReason.ILLEGAL_TRANSITION
    assert fixture.store.get(WORKFLOW, record.action_id) == decided


def test_a_rejection_cannot_be_overturned_by_a_second_reviewer(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.REJECT)
    fixture.store.roster.add(ReviewerId("E1002"))
    other = ReviewerSessionContext(reviewer_id=ReviewerId("E1002"), authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(other, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.ILLEGAL_TRANSITION


# --- time boxes ---------------------------------------------------------------------------------


def test_a_lapsed_pending_record_cannot_be_approved(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.clock.at = AT + timedelta(hours=72)
    with pytest.raises(ApprovalDecisionError) as excinfo:
        fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE)
    assert excinfo.value.reason is ApprovalRefusalReason.ILLEGAL_TRANSITION
    stored = fixture.store.get(WORKFLOW, record.action_id)
    assert stored is not None
    assert stored.status is ApprovalStatus.PENDING


def test_a_record_decided_inside_its_deadline_is_approved(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.clock.at = AT + timedelta(hours=71, minutes=59)
    decided = fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE)
    assert decided.status is ApprovalStatus.APPROVED


def test_an_approval_carries_the_configured_execution_window(fixture: Fixture) -> None:
    record = fixture.open()
    decided = fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE)
    assert decided.decided_at is not None
    assert decided.approved_expires_at == decided.decided_at + timedelta(hours=4)


# --- reviewer eligibility, re-checked ------------------------------------------------------------


def test_an_eligible_reviewer_reports_eligible(fixture: Fixture) -> None:
    assert fixture.store.reviewer_is_eligible(REVIEWER, REQUESTER) is True


def test_a_reviewer_removed_from_the_roster_reports_ineligible(fixture: Fixture) -> None:
    fixture.store.roster.discard(REVIEWER)
    assert fixture.store.reviewer_is_eligible(REVIEWER, REQUESTER) is False


def test_an_inactive_reviewer_reports_ineligible(fixture: Fixture) -> None:
    assert fixture.store.reviewer_is_eligible(INACTIVE, REQUESTER) is False


def test_the_requester_is_never_an_eligible_reviewer_of_their_own_action(fixture: Fixture) -> None:
    fixture.store.roster.add(ReviewerId(REQUESTER))
    assert fixture.store.reviewer_is_eligible(ReviewerId(REQUESTER), REQUESTER) is False
    assert fixture.store.reviewer_is_eligible(ReviewerId("e1042"), REQUESTER) is False


def test_a_reviewer_the_directory_does_not_know_reports_ineligible(fixture: Fixture) -> None:
    fixture.store.roster.add(ReviewerId("E0000"))
    assert fixture.store.reviewer_is_eligible(ReviewerId("E0000"), REQUESTER) is False


# --- one message, whatever the cause -------------------------------------------------------------


def test_every_decision_refusal_carries_the_same_message(fixture: Fixture) -> None:
    record = fixture.open()
    fixture.store.decide(fixture.reviewer, record.approval_id, ApprovalDecision.REJECT)
    messages = set()
    calls: list[Callable[[], object]] = [
        lambda: fixture.decide(None, record.approval_id, ApprovalDecision.APPROVE),
        lambda: fixture.decide(fixture.reviewer, record.approval_id, None),
        lambda: fixture.decide(
            ReviewerSessionContext(reviewer_id=OFF_ROSTER, authenticated_at=AT),
            record.approval_id,
            ApprovalDecision.APPROVE,
        ),
        lambda: fixture.decide(
            fixture.reviewer, ApprovalId("APR-nothing"), ApprovalDecision.APPROVE
        ),
        lambda: fixture.decide(fixture.reviewer, record.approval_id, ApprovalDecision.APPROVE),
    ]
    for call in calls:
        with pytest.raises(ApprovalDecisionError) as excinfo:
            call()
        messages.add(str(excinfo.value))
    assert len(messages) == 1


def test_the_recorded_policy_version_is_the_one_in_force(fixture: Fixture) -> None:
    record = fixture.open()
    assert record.policy_version == PolicyVersion(POLICY_VERSION)


# --- reviewer decisions on the audit trail ---------------------------------------------------


def _decisions(fixture: Fixture) -> list[AuditEvent]:
    return [
        event
        for event in fixture.audit.events()
        if event.event_type is AuditEventType.REVIEWER_DECISION
    ]


@pytest.mark.parametrize(
    ("decision", "status"),
    [
        (ApprovalDecision.APPROVE, ApprovalStatus.APPROVED),
        (ApprovalDecision.REJECT, ApprovalStatus.REJECTED),
    ],
)
def test_a_reviewer_decision_is_recorded(
    fixture: Fixture, decision: ApprovalDecision, status: ApprovalStatus
) -> None:
    record = fixture.open()
    fixture.decide(fixture.reviewer, record.approval_id, decision)
    events = _decisions(fixture)
    assert len(events) == 1
    recorded = events[0]
    assert recorded.actor_type is ActorType.REVIEWER
    assert recorded.actor_id == REVIEWER
    assert recorded.workflow_id == record.workflow_id
    assert recorded.action_id == record.action_id
    assert recorded.detail == status.value


def test_a_refused_decision_records_nothing(fixture: Fixture) -> None:
    # An off-roster reviewer is refused before any transition, so the trail carries no decision.
    record = fixture.open()
    stranger = ReviewerSessionContext(reviewer_id=ReviewerId("E9099"), authenticated_at=AT)
    with pytest.raises(ApprovalDecisionError):
        fixture.decide(stranger, record.approval_id, ApprovalDecision.APPROVE)
    assert _decisions(fixture) == []


def test_opening_a_record_writes_no_reviewer_decision(fixture: Fixture) -> None:
    # A pending record is not a decision. Nothing reaches the trail until a reviewer decides.
    fixture.open()
    assert _decisions(fixture) == []
