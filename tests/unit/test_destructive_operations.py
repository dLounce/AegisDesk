from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aegisdesk.action import (
    ModifyPermissionsProposal,
    ProposedAction,
    ProtectedActionProposal,
    RevokeAccessProposal,
)
from aegisdesk.approval import ApprovalDecision
from aegisdesk.backends.access import AccessBackend
from aegisdesk.backends.approvals import InMemoryApprovalStore
from aegisdesk.backends.audit import InMemoryAuditSink
from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import (
    load_action_reversibility,
    load_approval_policy,
    load_baseline_access,
    load_employees,
    load_operation_risk_tiers,
    load_resources,
    load_reviewers,
    load_risk_tiers,
)
from aegisdesk.backends.tickets import InMemoryTicketStore
from aegisdesk.domain.access import DestructiveReceipt, ExecutionReceipt
from aegisdesk.domain.enums import (
    AccessDuration,
    AgentName,
    AuditEventType,
    GuardOutcome,
    GuardRefusalReason,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    Reversibility,
)
from aegisdesk.domain.errors import (
    CurrentAccessMismatchError,
    NoCurrentAccessError,
    ProtectedExecutionError,
)
from aegisdesk.domain.ids import (
    ActionId,
    EmployeeId,
    ResourceId,
    ReviewerId,
    TicketId,
    WorkflowId,
)
from aegisdesk.guard import EXECUTION_CHANGE_MESSAGE, REFUSAL_MESSAGE, RuntimeGuard
from aegisdesk.session import authenticate_employee

AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)
WORKFLOW = WorkflowId("WF-0001")
SELF = "E1042"
OTHER = "E1043"
REVIEWER = ReviewerId("E1055")
JIRA = "jira"  # E1042 holds write baseline on jira, so a read grant resolves automatically.
WIKI = "wiki"  # A baseline resource the requester holds no grant on.


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


class RecordingAccess(AccessBackend):
    """Counts the side effects so exactly-once behaviour can be asserted."""

    def __init__(self) -> None:
        super().__init__()
        self.revoke_applies = 0
        self.modify_applies = 0

    def _apply_revoke(self, key: tuple[EmployeeId, ResourceId]) -> None:
        self.revoke_applies += 1
        super()._apply_revoke(key)

    def _apply_modify(self, key: tuple[EmployeeId, ResourceId], permission: Permission) -> None:
        self.modify_applies += 1
        super()._apply_modify(key, permission)


class FailingRevokeAccess(RecordingAccess):
    """The revoke side effect never confirms completion, leaving an uncertain attempt."""

    def _apply_revoke(self, key: tuple[EmployeeId, ResourceId]) -> None:
        self.revoke_applies += 1
        raise RuntimeError("revoke side effect did not confirm")


class Fixture:
    def __init__(self, access: RecordingAccess | None = None) -> None:
        self.clock = Clock(AT)
        self.audit = InMemoryAuditSink()
        self.directory = DirectoryBackend(load_employees(), load_baseline_access())
        self.catalog = ResourceCatalog(load_resources())
        self.tickets = InMemoryTicketStore(self.audit, clock=lambda: AT)
        self.access = access if access is not None else RecordingAccess()
        self.approvals = InMemoryApprovalStore(
            self.directory,
            load_reviewers(),
            load_approval_policy(),
            self.audit,
            self.clock,
        )
        self.guard = RuntimeGuard(
            self.directory,
            self.catalog,
            self.tickets,
            load_risk_tiers(),
            self.access,
            self.approvals,
            self.audit,
            self.clock,
            operation_risk_tiers=load_operation_risk_tiers(),
            reversibility=load_action_reversibility(),
        )
        self.ticket = self.tickets.create(EmployeeId(SELF), "access request").ticket_id
        self.session = authenticate_employee(SELF, self.directory, AT)
        self.reviewer = self.approvals  # decisions go through the store below

    def grant(self, resource: str = JIRA, permission: Permission = Permission.READ) -> Any:
        # A within-baseline grant resolves automatically, which is how current access is
        # established for a later revoke or modify to act on.
        outcome = self.guard.propose(
            AgentName.ESCALATION,
            self.session,
            WORKFLOW,
            ProposedAction(
                resource_id=ResourceId(resource),
                permission=permission,
                duration=AccessDuration.ONE_HOUR,
                ticket_id=self.ticket,
            ),
        )
        assert outcome.outcome is GuardOutcome.EXECUTED
        return outcome

    def propose(
        self, proposal: ProtectedActionProposal, agent: AgentName = AgentName.ESCALATION
    ) -> Any:
        return self.guard.propose(agent, self.session, WORKFLOW, proposal)

    def resume(self, proposal: ProtectedActionProposal) -> Any:
        return self.guard.execute_approved(AgentName.ESCALATION, self.session, WORKFLOW, proposal)

    def approve(self, approval_id: Any) -> None:
        from aegisdesk.session import ReviewerSessionContext

        reviewer = ReviewerSessionContext(reviewer_id=REVIEWER, authenticated_at=AT)
        self.approvals.decide(reviewer, approval_id, ApprovalDecision.APPROVE)

    def run(self, proposal: ProtectedActionProposal) -> Any:
        # propose -> approve -> resume, the full destructive path.
        pending = self.propose(proposal)
        assert pending.outcome is GuardOutcome.AWAITING_APPROVAL
        self.approve(pending.approval_id)
        return self.resume(proposal)


def revoke(
    resource: str = JIRA, permission: Permission = Permission.READ, ticket: TicketId | None = None
) -> RevokeAccessProposal:
    return RevokeAccessProposal(
        resource_id=ResourceId(resource),
        permission=permission,
        ticket_id=ticket if ticket is not None else TicketId("IT-0001"),
    )


def modify(
    resource: str = JIRA, permission: Permission = Permission.WRITE, ticket: TicketId | None = None
) -> ModifyPermissionsProposal:
    return ModifyPermissionsProposal(
        resource_id=ResourceId(resource),
        permission=permission,
        ticket_id=ticket if ticket is not None else TicketId("IT-0001"),
    )


@pytest.fixture
def fixture() -> Fixture:
    return Fixture()


# --- the payloads are typed and closed ------------------------------------------------------


@pytest.mark.parametrize("proposal_type", [RevokeAccessProposal, ModifyPermissionsProposal])
def test_a_destructive_proposal_cannot_carry_a_duration(proposal_type: type) -> None:
    # extra="forbid" means the field simply does not exist to be set, rather than being ignored.
    with pytest.raises(ValidationError):
        proposal_type(
            resource_id=ResourceId(JIRA),
            permission=Permission.READ,
            duration=AccessDuration.ONE_HOUR,
            ticket_id=TicketId("IT-0001"),
        )


@pytest.mark.parametrize("proposal_type", [RevokeAccessProposal, ModifyPermissionsProposal])
def test_a_model_cannot_supply_reversibility(proposal_type: type) -> None:
    # Reversibility is trusted configuration; a proposal has no field for it, so a model claiming
    # an operation is reversible cannot change how the runtime treats it.
    with pytest.raises(ValidationError):
        proposal_type(
            resource_id=ResourceId(JIRA),
            permission=Permission.READ,
            ticket_id=TicketId("IT-0001"),
            reversibility="reversible",
        )


def test_a_destructive_proposal_names_no_employee() -> None:
    # No field naming an employee, so acting on somebody else's access is not expressible. The
    # requester is resolved from the session, exactly as for a grant.
    for proposal_type in (RevokeAccessProposal, ModifyPermissionsProposal):
        assert set(proposal_type.model_fields) == {
            "operation",
            "resource_id",
            "permission",
            "ticket_id",
        }


def test_distinct_operations_produce_distinct_action_identities() -> None:
    # Same resource, permission, ticket and workflow across grant, revoke and modify still yield
    # three different action identities, because the operation is inside the canonical form and
    # the destructive forms carry no duration.
    fixture = Fixture()
    fixture.grant(JIRA, Permission.READ)
    grant_id = fixture.grant(JIRA, Permission.READ).action_id
    revoke_id = fixture.propose(revoke(JIRA, Permission.READ, fixture.ticket)).action_id
    modify_id = fixture.propose(modify(JIRA, Permission.READ, fixture.ticket)).action_id
    assert len({grant_id, revoke_id, modify_id}) == 3


# --- capability binding ---------------------------------------------------------------------


@pytest.mark.parametrize("agent", [AgentName.RESOLVER, AgentName.ROUTER])
@pytest.mark.parametrize("proposal", [revoke(), modify()])
def test_only_escalation_may_propose_a_destructive_operation(
    agent: AgentName, proposal: ProtectedActionProposal, fixture: Fixture
) -> None:
    outcome = fixture.propose(proposal, agent=agent)
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.MISSING_CAPABILITY
    assert fixture.access.revoke_applies == 0
    assert fixture.access.modify_applies == 0


# --- both operations always require approval -------------------------------------------------


def test_revoke_requires_approval_even_within_baseline(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    outcome = fixture.propose(revoke(JIRA, Permission.READ, fixture.ticket))
    assert outcome.outcome is GuardOutcome.AWAITING_APPROVAL
    assert outcome.decision is not None
    assert outcome.decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert outcome.decision.reason is PolicyReason.REVOKE_REQUIRES_APPROVAL


def test_modify_requires_approval_even_within_baseline(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    outcome = fixture.propose(modify(JIRA, Permission.WRITE, fixture.ticket))
    assert outcome.outcome is GuardOutcome.AWAITING_APPROVAL
    assert outcome.decision is not None
    assert outcome.decision.reason is PolicyReason.MODIFY_REQUIRES_APPROVAL


# --- current-access preconditions ------------------------------------------------------------


def test_revoke_leaves_no_permission(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    outcome = fixture.run(revoke(JIRA, Permission.READ, fixture.ticket))
    assert outcome.outcome is GuardOutcome.EXECUTED
    assert outcome.access_change is not None
    assert outcome.access_change.previous_permission is Permission.READ
    assert outcome.access_change.resulting_permission is None
    assert fixture.access.get_current_permission(EmployeeId(SELF), ResourceId(JIRA)) is None


def test_revoke_requires_the_matching_current_permission(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    # The requester holds read, so a revoke naming admin does not match the authoritative state.
    outcome = fixture.run(revoke(JIRA, Permission.ADMIN, fixture.ticket))
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.CURRENT_ACCESS_MISMATCH
    # The access it does hold is untouched by the refused revoke.
    assert fixture.access.get_current_permission(EmployeeId(SELF), ResourceId(JIRA)) is (
        Permission.READ
    )


def test_modify_records_previous_and_resulting_permission(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    outcome = fixture.run(modify(JIRA, Permission.WRITE, fixture.ticket))
    assert outcome.outcome is GuardOutcome.EXECUTED
    assert outcome.access_change is not None
    assert outcome.access_change.previous_permission is Permission.READ
    assert outcome.access_change.resulting_permission is Permission.WRITE
    assert fixture.access.get_current_permission(EmployeeId(SELF), ResourceId(JIRA)) is (
        Permission.WRITE
    )


def test_modify_requires_existing_current_access(fixture: Fixture) -> None:
    # The requester holds nothing on wiki, so there is no permission to re-point.
    outcome = fixture.run(modify(WIKI, Permission.WRITE, fixture.ticket))
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.NO_CURRENT_ACCESS


# --- the destructive ledger ------------------------------------------------------------------


def test_a_completed_revoke_replay_returns_the_recorded_result(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    first = fixture.run(revoke(JIRA, Permission.READ, fixture.ticket))
    assert first.outcome is GuardOutcome.EXECUTED
    # A retried resume — a restarted worker, a network retry — returns the recorded change rather
    # than performing a second revoke.
    again = fixture.resume(revoke(JIRA, Permission.READ, fixture.ticket))
    assert again.outcome is GuardOutcome.EXECUTED
    assert again.access_change == first.access_change
    assert fixture.access.revoke_applies == 1


def test_an_approved_destructive_resume_executes_exactly_once(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    fixture.run(modify(JIRA, Permission.WRITE, fixture.ticket))
    for _ in range(3):
        fixture.resume(modify(JIRA, Permission.WRITE, fixture.ticket))
    assert fixture.access.modify_applies == 1
    executed = [
        event
        for event in fixture.audit.events()
        if event.event_type is AuditEventType.EXECUTED
        and event.decision is not None
        and event.decision.operation is ProtectedOperation.MODIFY_PERMISSIONS
    ]
    assert len(executed) == 1


def test_an_uncertain_destructive_attempt_refuses_replay() -> None:
    fixture = Fixture(access=FailingRevokeAccess())
    fixture.grant(JIRA, Permission.READ)
    pending = fixture.propose(revoke(JIRA, Permission.READ, fixture.ticket))
    fixture.approve(pending.approval_id)

    # The first attempt's side effect does not confirm completion, so the failure propagates.
    with pytest.raises(RuntimeError):
        fixture.resume(revoke(JIRA, Permission.READ, fixture.ticket))

    # The retry is refused rather than performing a second irreversible side effect.
    outcome = fixture.resume(revoke(JIRA, Permission.READ, fixture.ticket))
    assert outcome.outcome is GuardOutcome.REFUSED
    assert outcome.refusal_reason is GuardRefusalReason.UNCERTAIN_DESTRUCTIVE_REPLAY


# --- audit records operation and reversibility -----------------------------------------------


def test_a_destructive_execution_records_its_operation_and_reversibility(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    fixture.run(revoke(JIRA, Permission.READ, fixture.ticket))
    # The grant that established current access also recorded an executed event, so the revoke's
    # is isolated by its operation.
    executed = [
        e
        for e in fixture.audit.events()
        if e.event_type is AuditEventType.EXECUTED
        and e.decision is not None
        and e.decision.operation is ProtectedOperation.REVOKE_ACCESS
    ]
    assert len(executed) == 1
    assert executed[0].detail == Reversibility.IRREVERSIBLE.value


# --- what the model is told ------------------------------------------------------------------


def test_a_refused_destructive_operation_reveals_nothing(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    refused = fixture.run(revoke(JIRA, Permission.ADMIN, fixture.ticket))
    assert refused.message == REFUSAL_MESSAGE


def test_a_completed_destructive_operation_does_not_say_granted(fixture: Fixture) -> None:
    fixture.grant(JIRA, Permission.READ)
    outcome = fixture.run(revoke(JIRA, Permission.READ, fixture.ticket))
    assert outcome.message == EXECUTION_CHANGE_MESSAGE
    assert outcome.message != REFUSAL_MESSAGE


# --- cross-employee targeting stays impossible -----------------------------------------------


def test_a_destructive_operation_acts_only_on_the_session_requester() -> None:
    # Two employees hold read on jira. One revoking their own access does not touch the other's,
    # because the requester is resolved from the session and there is no field to name anyone else.
    fixture = Fixture()
    other_ticket = fixture.tickets.create(EmployeeId(OTHER), "unrelated").ticket_id
    other_session = authenticate_employee(OTHER, fixture.directory, AT)
    fixture.guard.propose(
        AgentName.ESCALATION,
        other_session,
        WORKFLOW,
        ProposedAction(
            resource_id=ResourceId(JIRA),
            permission=Permission.READ,
            duration=AccessDuration.ONE_HOUR,
            ticket_id=other_ticket,
        ),
    )
    fixture.grant(JIRA, Permission.READ)  # SELF now also holds read on jira

    fixture.run(revoke(JIRA, Permission.READ, fixture.ticket))
    assert fixture.access.get_current_permission(EmployeeId(SELF), ResourceId(JIRA)) is None
    assert fixture.access.get_current_permission(EmployeeId(OTHER), ResourceId(JIRA)) is (
        Permission.READ
    )


# --- the backend refuses receipts built outside the guard ------------------------------------


def test_a_destructive_receipt_built_outside_the_guard_is_refused() -> None:
    backend = RecordingAccess()
    backend.claim_minting_authority()
    forged = DestructiveReceipt(
        action_id=ActionId("ACT-forged"),
        operation=ProtectedOperation.REVOKE_ACCESS,
        requester_id=EmployeeId(SELF),
        resource_id=ResourceId(JIRA),
        permission=Permission.READ,
        authorised_at=AT,
    )
    with pytest.raises(ProtectedExecutionError):
        backend.revoke(forged, "not-the-key")


def test_a_grant_receipt_cannot_be_passed_to_revoke() -> None:
    backend = RecordingAccess()
    key = backend.claim_minting_authority()
    grant_shaped: Any = ExecutionReceipt(
        action_id=ActionId("ACT-0001"),
        requester_id=EmployeeId(SELF),
        resource_id=ResourceId(JIRA),
        permission=Permission.READ,
        duration=AccessDuration.ONE_HOUR,
        authorised_at=AT,
    )
    with pytest.raises(ProtectedExecutionError):
        backend.revoke(grant_shaped, key)


def test_the_backend_enforces_current_access_directly() -> None:
    # Defence in depth: even called directly with a valid receipt and key, the backend refuses a
    # revoke that does not match current access and a modify with nothing to change.
    backend = RecordingAccess()
    key = backend.claim_minting_authority()
    receipt = DestructiveReceipt(
        action_id=ActionId("ACT-0001"),
        operation=ProtectedOperation.REVOKE_ACCESS,
        requester_id=EmployeeId(SELF),
        resource_id=ResourceId(JIRA),
        permission=Permission.READ,
        authorised_at=AT,
    )
    with pytest.raises(CurrentAccessMismatchError):
        backend.revoke(receipt, key)
    modify_receipt = receipt.model_copy(update={"operation": ProtectedOperation.MODIFY_PERMISSIONS})
    with pytest.raises(NoCurrentAccessError):
        backend.modify(modify_receipt, key)
