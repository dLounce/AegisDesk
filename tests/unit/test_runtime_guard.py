from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegisdesk.action import ProposedAction
from aegisdesk.backends.access import AccessBackend
from aegisdesk.backends.approvals import InMemoryApprovalStore
from aegisdesk.backends.audit import InMemoryAuditSink
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import (
    load_approval_policy,
    load_baseline_access,
    load_employees,
    load_resources,
    load_reviewers,
    load_risk_tiers,
)
from aegisdesk.backends.tickets import InMemoryTicketStore
from aegisdesk.domain.access import ExecutionReceipt
from aegisdesk.domain.enums import (
    AccessDuration,
    ActorType,
    AgentName,
    AuditEventType,
    GuardOutcome,
    GuardRefusalReason,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    ResourceClass,
    RiskTier,
)
from aegisdesk.domain.errors import ProtectedExecutionError
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId, ReviewerId, TicketId, WorkflowId
from aegisdesk.guard import PENDING_MESSAGE, REFUSAL_MESSAGE, RuntimeGuard
from aegisdesk.session import (
    ReviewerSessionContext,
    authenticate_employee,
)

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WORKFLOW = WorkflowId("WF-0001")

# Distinguishes "no proposal supplied to the helper" from a proposal that is literally None,
# which is one of the malformed arguments under test.
_UNSET: Any = object()

SELF = "E1042"
OTHER = "E1043"
INACTIVE = "E9099"


class RecordingDirectory(DirectoryBackend):
    reads = 0

    def get_employee(self, requester_id: EmployeeId, target_id: EmployeeId) -> Any:
        self.reads += 1
        return super().get_employee(requester_id, target_id)

    def get_baseline_permission(
        self, requester_id: EmployeeId, target_id: EmployeeId, resource_id: ResourceId
    ) -> Any:
        self.reads += 1
        return super().get_baseline_permission(requester_id, target_id, resource_id)


class RecordingCatalog(ResourceCatalog):
    reads = 0

    def get(self, resource_id: ResourceId) -> Any:
        self.reads += 1
        return super().get(resource_id)


class RecordingAccess(AccessBackend):
    writes = 0

    def grant(self, receipt: ExecutionReceipt, minting_key: str) -> Any:
        self.writes += 1
        return super().grant(receipt, minting_key)


class Clock:
    """A clock the test moves, so the guard reads time from one place it does not choose."""

    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


class RaisingAuditSink(InMemoryAuditSink):
    """A recording boundary that is down: every write raises."""

    def record(self, event: Any) -> Any:
        raise RuntimeError("audit sink is down")


class Fixture:
    def __init__(self, risk_tiers: Any = None, audit: Any = None) -> None:
        self.clock = Clock(AT)
        self.audit = InMemoryAuditSink() if audit is None else audit
        self.directory = RecordingDirectory(load_employees(), load_baseline_access())
        self.catalog = RecordingCatalog(load_resources())
        self.tickets = InMemoryTicketStore(self.audit, clock=lambda: AT)
        self.access = RecordingAccess()
        self.approvals = InMemoryApprovalStore(
            self.directory, load_reviewers(), load_approval_policy(), self.audit, self.clock
        )
        self.guard = RuntimeGuard(
            self.directory,
            self.catalog,
            self.tickets,
            load_risk_tiers() if risk_tiers is None else risk_tiers,
            self.access,
            self.approvals,
            self.audit,
            self.clock,
        )
        self.own_ticket = self.tickets.create(EmployeeId(SELF), "access request").ticket_id
        self.other_ticket = self.tickets.create(EmployeeId(OTHER), "unrelated").ticket_id
        self.inactive_ticket = self.tickets.create(EmployeeId(INACTIVE), "stale").ticket_id
        self.session = authenticate_employee(SELF, self.directory, AT)
        # Authenticating the session read the directory. The counters exist to observe what the
        # guard does, so they start from zero once the fixture is built.
        self.directory.reads = 0
        self.catalog.reads = 0
        self.access.writes = 0

    def propose(
        self,
        *,
        agent: AgentName = AgentName.ESCALATION,
        session: Any = _UNSET,
        resource_id: str = "jira",
        permission: Permission = Permission.READ,
        duration: AccessDuration = AccessDuration.ONE_HOUR,
        ticket_id: TicketId | None = None,
        action: Any = _UNSET,
    ) -> Any:
        proposal = (
            action
            if action is not _UNSET
            else ProposedAction(
                operation=ProtectedOperation.GRANT_ACCESS,
                resource_id=ResourceId(resource_id),
                permission=permission,
                duration=duration,
                ticket_id=ticket_id if ticket_id is not None else self.own_ticket,
            )
        )
        return self.guard.propose(
            agent, self.session if session is _UNSET else session, WORKFLOW, proposal
        )


@pytest.fixture
def fixture() -> Fixture:
    return Fixture()


# --- capability binding ----------------------------------------------------------------------


def test_the_escalation_agent_may_propose_and_the_action_executes(fixture: Fixture) -> None:
    outcome = fixture.propose()
    assert outcome.outcome is GuardOutcome.EXECUTED
    assert outcome.decision is not None
    assert outcome.decision.reason is PolicyReason.WITHIN_BASELINE
    assert outcome.grant is not None
    assert outcome.grant.employee_id == EmployeeId(SELF)


@pytest.mark.parametrize("agent", [AgentName.RESOLVER, AgentName.ROUTER])
def test_an_agent_without_the_capability_is_refused(agent: AgentName, fixture: Fixture) -> None:
    outcome = fixture.propose(agent=agent)
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.MISSING_CAPABILITY
    assert fixture.access.writes == 0


def test_the_capability_check_precedes_any_backend_read(fixture: Fixture) -> None:
    # A caller without the capability learns nothing about the directory, the catalogue or the
    # ticket store by watching what the guard does next.
    fixture.propose(agent=AgentName.RESOLVER)
    assert fixture.directory.reads == 0
    assert fixture.catalog.reads == 0


def test_a_refusal_before_resolution_echoes_nothing(fixture: Fixture) -> None:
    outcome = fixture.propose(agent=AgentName.RESOLVER)
    assert outcome.resolved is None
    assert outcome.action_id is None
    assert outcome.argument_digest is None
    assert outcome.decision is None


# --- the guard resolves; the proposal supplies nothing it owns --------------------------------


def test_the_requester_comes_from_the_session_rather_than_the_proposal(fixture: Fixture) -> None:
    other_session = authenticate_employee(OTHER, fixture.directory, AT)
    outcome = fixture.propose(session=other_session, ticket_id=fixture.other_ticket)
    assert outcome.outcome is GuardOutcome.EXECUTED
    assert outcome.grant is not None
    assert outcome.grant.employee_id == EmployeeId(OTHER)
    assert outcome.resolved is not None
    assert outcome.resolved.requester_id == EmployeeId(OTHER)


def test_the_resource_is_resolved_through_the_catalogue(fixture: Fixture) -> None:
    fixture.propose()
    assert fixture.catalog.reads == 1


def test_an_unresolved_resource_is_refused_before_policy(fixture: Fixture) -> None:
    # The guard has no risk tier for a resource with no class, and inventing one is exactly the
    # value it must not hold, so an unknown identifier stops here.
    outcome = fixture.propose(resource_id="prod-db-staging")
    assert outcome.refusal_reason is GuardRefusalReason.UNRESOLVED_RESOURCE
    assert outcome.decision is None


def test_the_baseline_is_read_from_the_directory(fixture: Fixture) -> None:
    # E1042 holds write on jira, so read resolves within baseline and admin does not.
    assert fixture.propose(permission=Permission.READ).outcome is GuardOutcome.EXECUTED
    escalated = fixture.propose(permission=Permission.ADMIN)
    assert escalated.decision is not None
    assert escalated.decision.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


def test_a_resource_the_requester_holds_no_baseline_on_escalates(fixture: Fixture) -> None:
    outcome = fixture.propose(resource_id="finance-reports")
    assert outcome.outcome is GuardOutcome.AWAITING_APPROVAL
    assert outcome.decision is not None
    assert outcome.decision.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


def test_the_risk_tier_comes_from_configuration(fixture: Fixture) -> None:
    outcome = fixture.propose()
    assert outcome.decision is not None
    assert outcome.decision.risk_tier is RiskTier.LOW


def test_altering_the_configuration_alters_the_recorded_tier_and_nothing_else() -> None:
    # The tier is configuration the guard reads, not a value any caller supplies, and policy
    # records it without consulting it.
    tiers = dict(load_risk_tiers())
    tiers[(ResourceClass.BASELINE, Permission.READ, AccessDuration.ONE_HOUR)] = RiskTier.CRITICAL
    outcome = Fixture(risk_tiers=tiers).propose()
    assert outcome.outcome is GuardOutcome.EXECUTED
    assert outcome.decision is not None
    assert outcome.decision.risk_tier is RiskTier.CRITICAL


def test_an_unclassified_triple_fails_closed() -> None:
    outcome = Fixture(risk_tiers={}).propose()
    assert outcome.refusal_reason is GuardRefusalReason.UNCLASSIFIED_RISK
    assert outcome.decision is None


# --- ticket scoping ----------------------------------------------------------------------------


def test_a_proposal_attached_to_another_employees_ticket_is_refused(fixture: Fixture) -> None:
    # Otherwise a proposal reaches a reviewer under a ticket number that misdescribes it.
    outcome = fixture.propose(ticket_id=fixture.other_ticket)
    assert outcome.refusal_reason is GuardRefusalReason.UNRESOLVED_TICKET
    assert fixture.access.writes == 0


def test_a_ticket_that_does_not_exist_is_refused(fixture: Fixture) -> None:
    outcome = fixture.propose(ticket_id=TicketId("IT-9999"))
    assert outcome.refusal_reason is GuardRefusalReason.UNRESOLVED_TICKET


# --- policy outcomes ----------------------------------------------------------------------------


def test_a_privileged_resource_pauses_for_approval_and_does_not_execute(fixture: Fixture) -> None:
    outcome = fixture.propose(resource_id="prod-db")
    assert outcome.outcome is GuardOutcome.AWAITING_APPROVAL
    assert outcome.refusal_reason is None
    assert outcome.decision is not None
    assert outcome.decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert outcome.decision.reason is PolicyReason.PRIVILEGED_RESOURCE
    assert fixture.access.writes == 0
    assert outcome.grant is None


def test_an_approval_requiring_proposal_keeps_its_identity_for_the_audit_path(
    fixture: Fixture,
) -> None:
    # The approval record binds to these values, so they travel on the pending outcome even
    # though nothing executed.
    outcome = fixture.propose(resource_id="prod-db", duration=AccessDuration.PERMANENT)
    assert outcome.resolved is not None
    assert outcome.action_id is not None
    assert outcome.argument_digest is not None
    assert outcome.approval_id is not None
    assert outcome.decision is not None
    assert outcome.decision.reason is PolicyReason.STANDING_PRIVILEGED_ACCESS


def test_an_inactive_requester_is_denied(fixture: Fixture) -> None:
    session = authenticate_employee(INACTIVE, fixture.directory, AT)
    outcome = fixture.propose(
        session=session, resource_id="wiki", ticket_id=fixture.inactive_ticket
    )
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.decision is not None
    assert outcome.decision.effect is PolicyEffect.DENY
    assert outcome.decision.reason is PolicyReason.REQUESTER_INACTIVE
    assert fixture.access.writes == 0


# --- what the model is told ----------------------------------------------------------------------


def test_the_refusal_text_is_the_same_whatever_the_reason(fixture: Fixture) -> None:
    # A refusal that named its cause would let a compromised agent search the argument space by
    # comparing replies until one combination is permitted.
    inactive = authenticate_employee(INACTIVE, fixture.directory, AT)
    refusals = [
        fixture.propose(agent=AgentName.RESOLVER),
        fixture.propose(resource_id="prod-db-staging"),
        fixture.propose(ticket_id=fixture.other_ticket),
        fixture.propose(session=inactive, ticket_id=fixture.inactive_ticket),
        fixture.propose(session=None),
        fixture.propose(action=None),
    ]
    assert {outcome.message for outcome in refusals} == {REFUSAL_MESSAGE}
    assert all(outcome.outcome is GuardOutcome.REFUSED for outcome in refusals)


def test_a_pending_action_is_told_apart_from_a_refused_one(fixture: Fixture) -> None:
    # The one distinction the model may draw, because the workflow pauses and the employee is
    # told a human is looking. It still names no resource, no rule and no reviewer.
    pending = fixture.propose(resource_id="prod-db")
    assert pending.message == PENDING_MESSAGE
    assert pending.message != REFUSAL_MESSAGE


def test_the_precise_reason_is_kept_for_the_audit_trail(fixture: Fixture) -> None:
    inactive = authenticate_employee(INACTIVE, fixture.directory, AT)
    reasons = {
        fixture.propose(agent=AgentName.RESOLVER).refusal_reason,
        fixture.propose(resource_id="prod-db-staging").refusal_reason,
        fixture.propose(ticket_id=fixture.other_ticket).refusal_reason,
        fixture.propose(session=inactive, ticket_id=fixture.inactive_ticket).refusal_reason,
    }
    assert reasons == {
        GuardRefusalReason.MISSING_CAPABILITY,
        GuardRefusalReason.UNRESOLVED_RESOURCE,
        GuardRefusalReason.UNRESOLVED_TICKET,
        GuardRefusalReason.POLICY_REFUSED,
    }


def test_the_message_cannot_be_set_by_a_caller(fixture: Fixture) -> None:
    outcome = fixture.propose(resource_id="prod-db")
    with pytest.raises(ValueError):
        outcome.message = "granted"


# --- malformed input ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "argument",
    [
        None,
        "grant_access prod-db admin permanent",
        {"operation": "grant_access", "resource_id": "prod-db"},
        object(),
    ],
)
def test_anything_that_is_not_a_proposal_fails_closed(argument: Any, fixture: Fixture) -> None:
    outcome = fixture.propose(action=argument)
    assert outcome.refusal_reason is GuardRefusalReason.MALFORMED_PROPOSAL
    assert fixture.directory.reads == 0
    assert fixture.access.writes == 0


# --- repeatability and exactly-once -------------------------------------------------------------


def test_the_path_before_execution_repeats_without_writing(fixture: Fixture) -> None:
    # Whatever runs before a pause runs again on resume, so running it twice must produce the
    # same values and touch nothing.
    first = fixture.propose(resource_id="prod-db")
    second = fixture.propose(resource_id="prod-db")
    assert first.action_id == second.action_id
    assert first.argument_digest == second.argument_digest
    assert first.decision == second.decision
    assert fixture.access.writes == 0


def test_a_repeated_execution_produces_one_grant(fixture: Fixture) -> None:
    first = fixture.propose()
    second = fixture.propose()
    assert first.action_id == second.action_id
    assert second.grant is first.grant
    assert fixture.access.writes == 2
    assert fixture.access.grant_for(first.action_id) is first.grant


def test_two_distinct_actions_receive_distinct_identifiers(fixture: Fixture) -> None:
    first = fixture.propose(permission=Permission.READ)
    second = fixture.propose(resource_id="wiki", permission=Permission.READ)
    assert first.action_id != second.action_id
    assert second.grant is not first.grant


def test_a_later_clock_changes_the_decision_record_but_not_the_binding(fixture: Fixture) -> None:
    # Comparing whole decision records on resume cannot work, because evaluated_at legitimately
    # differs between the proposing pass and the resuming one. The binding values do not.
    first = fixture.propose(resource_id="prod-db")
    fixture.clock.at = AT + timedelta(hours=2)
    second = fixture.propose(resource_id="prod-db")
    assert first.decision != second.decision
    assert first.action_id == second.action_id
    assert first.argument_digest == second.argument_digest
    assert first.decision is not None
    assert second.decision is not None
    assert (first.decision.policy_version, first.decision.effect, first.decision.reason) == (
        second.decision.policy_version,
        second.decision.effect,
        second.decision.reason,
    )


# --- identity is checked, not taken on trust -------------------------------------------------


class LookalikeSession:
    """Carries an employee_id and nothing else that makes it a session."""

    def __init__(self, employee_id: str) -> None:
        self.employee_id = EmployeeId(employee_id)
        self.authenticated_at = AT


@pytest.mark.parametrize(
    "session",
    [
        None,
        "E1042",
        {"employee_id": "E1042"},
        LookalikeSession("E1042"),
        LookalikeSession("E1043"),
        ReviewerSessionContext(reviewer_id=ReviewerId("E1055"), authenticated_at=AT),
    ],
)
def test_anything_that_is_not_a_session_fails_closed(session: Any, fixture: Fixture) -> None:
    # An object merely carrying an employee_id would pass every later check, because the
    # directory scopes a read to the requester the caller named. That is the identity claim the
    # session boundary exists to refuse.
    outcome = fixture.propose(session=session)
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.UNTRUSTED_SESSION
    assert fixture.directory.reads == 0
    assert fixture.catalog.reads == 0
    assert fixture.access.writes == 0


def test_a_lookalike_session_cannot_grant_access_to_another_employee(fixture: Fixture) -> None:
    outcome = fixture.propose(session=LookalikeSession("E1043"), ticket_id=fixture.other_ticket)
    assert outcome.grant is None
    assert fixture.access.grant_for(ActionId("ACT-0001")) is None


def test_identity_is_checked_before_the_proposal(fixture: Fixture) -> None:
    # Both refusals are pure, but identity is the more fundamental of the two and is reported
    # when both are wrong, so an audit line names the reason that matters.
    outcome = fixture.propose(session=None, action=None)
    assert outcome.refusal_reason is GuardRefusalReason.UNTRUSTED_SESSION


# --- protected execution is reachable only through the bound guard ----------------------------


def test_a_receipt_built_outside_the_guard_is_refused(fixture: Fixture) -> None:
    # The receipt class is importable, so this receipt constructs. It is refused because the
    # caller does not hold the key the backend issued to its one minting authority.
    forged = ExecutionReceipt(
        action_id=ActionId("ACT-forged"),
        requester_id=EmployeeId(SELF),
        resource_id=ResourceId("prod-db"),
        permission=Permission.ADMIN,
        duration=AccessDuration.PERMANENT,
        authorised_at=AT,
    )
    with pytest.raises(ProtectedExecutionError):
        fixture.access.grant(forged, "minting-key")
    assert fixture.access.grant_for(ActionId("ACT-forged")) is None


def test_a_second_guard_cannot_bind_to_a_backend_that_has_an_authority(
    fixture: Fixture,
) -> None:
    with pytest.raises(ProtectedExecutionError):
        RuntimeGuard(
            fixture.directory,
            fixture.catalog,
            fixture.tickets,
            load_risk_tiers(),
            fixture.access,
            fixture.approvals,
            fixture.audit,
            fixture.clock,
        )


def test_the_bound_guard_still_executes(fixture: Fixture) -> None:
    # The key the guard claimed at construction is what makes its own receipts usable.
    assert fixture.propose().outcome is GuardOutcome.EXECUTED


# --- audit trail (propose side) --------------------------------------------------------------


def _types(fixture: Fixture) -> list[AuditEventType]:
    return [event.event_type for event in fixture.audit.events()]


def test_an_executed_action_records_one_executed_event(fixture: Fixture) -> None:
    outcome = fixture.propose()
    assert outcome.outcome is GuardOutcome.EXECUTED
    events = fixture.audit.events()
    assert [event.event_type for event in events] == [AuditEventType.EXECUTED]
    recorded = events[0]
    assert recorded.actor_type is ActorType.RUNTIME
    assert recorded.action_id == outcome.action_id
    assert recorded.decision is not None
    assert recorded.decision.reason is PolicyReason.WITHIN_BASELINE


def test_the_executed_event_is_written_before_the_grant_is_minted() -> None:
    # Fail-closed: if the recording boundary is down, the write raises and no grant is issued.
    fixture = Fixture(audit=RaisingAuditSink())
    with pytest.raises(RuntimeError):
        fixture.propose()
    assert fixture.access.writes == 0


def test_a_repeated_execution_records_one_event(fixture: Fixture) -> None:
    # The pre-pause pass re-runs on resume. The executed event is keyed on the action identifier,
    # so the second pass records nothing new and the grant is the same one.
    first = fixture.propose()
    second = fixture.propose()
    assert first.grant == second.grant
    assert _types(fixture) == [AuditEventType.EXECUTED]


def test_a_pending_action_records_the_proposal_and_the_pause(fixture: Fixture) -> None:
    outcome = fixture.propose(
        resource_id="prod-db", permission=Permission.ADMIN, duration=AccessDuration.EIGHT_HOURS
    )
    assert outcome.outcome is GuardOutcome.AWAITING_APPROVAL
    assert _types(fixture) == [
        AuditEventType.PROPOSAL_PERSISTED,
        AuditEventType.AWAITING_APPROVAL,
    ]
    for event in fixture.audit.events():
        assert event.action_id == outcome.action_id
        assert event.actor_type is ActorType.RUNTIME


def test_a_replayed_pending_proposal_records_nothing_new(fixture: Fixture) -> None:
    fixture.propose(
        resource_id="prod-db", permission=Permission.ADMIN, duration=AccessDuration.EIGHT_HOURS
    )
    fixture.propose(
        resource_id="prod-db", permission=Permission.ADMIN, duration=AccessDuration.EIGHT_HOURS
    )
    assert _types(fixture) == [
        AuditEventType.PROPOSAL_PERSISTED,
        AuditEventType.AWAITING_APPROVAL,
    ]


def test_a_refusal_reaches_the_trail_while_the_model_sees_one_sentence(fixture: Fixture) -> None:
    outcome = fixture.propose(agent=AgentName.RESOLVER)
    assert outcome.message == REFUSAL_MESSAGE
    events = fixture.audit.events()
    assert [event.event_type for event in events] == [AuditEventType.REFUSED]
    # The precise reason travels on the trail, never in the message the model is handed.
    assert events[0].refusal_reason == GuardRefusalReason.MISSING_CAPABILITY.value
    assert REFUSAL_MESSAGE not in (events[0].refusal_reason or "")


def test_a_pre_resolution_refusal_has_no_action_id_and_is_recorded_each_time(
    fixture: Fixture,
) -> None:
    # No action identity means no key to deduplicate under, so each genuine attempt is its own
    # line rather than being folded into one.
    fixture.propose(agent=AgentName.RESOLVER)
    fixture.propose(agent=AgentName.RESOLVER)
    events = fixture.audit.events()
    assert [event.event_type for event in events] == [
        AuditEventType.REFUSED,
        AuditEventType.REFUSED,
    ]
    assert all(event.action_id is None for event in events)


def test_a_resolved_refusal_carries_its_action_id_and_deduplicates(fixture: Fixture) -> None:
    # An inactive requester is denied by policy after resolution, so the refusal names an action
    # and is keyed. A replay of the same refused action records one line.
    session = authenticate_employee(INACTIVE, fixture.directory, AT)
    first = fixture.propose(session=session, ticket_id=fixture.inactive_ticket)
    fixture.propose(session=session, ticket_id=fixture.inactive_ticket)
    assert first.refusal_reason is GuardRefusalReason.POLICY_REFUSED
    events = fixture.audit.events()
    assert [event.event_type for event in events] == [AuditEventType.REFUSED]
    assert events[0].action_id == first.action_id


def test_a_refusal_stands_even_when_the_trail_cannot_record_it() -> None:
    # Best-effort for a non-executing outcome: a failed write must not convert a refusal into a
    # raised exception.
    fixture = Fixture(audit=RaisingAuditSink())
    outcome = fixture.propose(agent=AgentName.RESOLVER)
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.MISSING_CAPABILITY
