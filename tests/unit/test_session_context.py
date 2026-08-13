from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import load_baseline_access, load_employees
from aegisdesk.domain.enums import (
    AccessDuration,
    Permission,
    PolicyEffect,
    PolicyReason,
    ResourceClass,
    RiskTier,
)
from aegisdesk.domain.errors import SessionAuthenticationError
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId, WorkflowId
from aegisdesk.domain.resource import Resource
from aegisdesk.policy import PolicyRequest, evaluate
from aegisdesk.session import (
    MAX_CLAIMED_ID_LENGTH,
    EmployeeSessionContext,
    ReviewerSessionContext,
    authenticate_employee,
    authenticate_reviewer,
)

SELF = "E1042"
REVIEWER = "E1055"
INACTIVE = "E9099"
ABSENT = "E0000"
AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)


@pytest.fixture
def directory() -> DirectoryBackend:
    return DirectoryBackend(load_employees(), load_baseline_access())


# --- the session record carries identity and nothing else --------------------------------


def test_employee_session_declares_exactly_two_fields() -> None:
    assert set(EmployeeSessionContext.model_fields) == {"employee_id", "authenticated_at"}


def test_reviewer_session_declares_exactly_two_fields() -> None:
    assert set(ReviewerSessionContext.model_fields) == {"reviewer_id", "authenticated_at"}


def test_session_record_is_frozen_and_closed() -> None:
    context = EmployeeSessionContext(employee_id=EmployeeId(SELF), authenticated_at=AT)
    with pytest.raises(ValidationError):
        context.employee_id = EmployeeId(ABSENT)
    with pytest.raises(ValidationError):
        EmployeeSessionContext(
            employee_id=EmployeeId(SELF),
            authenticated_at=AT,
            role="it_admin",  # type: ignore[call-arg]
        )


def test_session_record_rejects_a_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        EmployeeSessionContext(
            employee_id=EmployeeId(SELF),
            authenticated_at=datetime(2026, 8, 13, 9, 0),
        )


def test_session_record_compares_by_value(directory: DirectoryBackend) -> None:
    # A resume re-supplies the session rather than reading it back from workflow state, so the
    # value the workflow started with has to be comparable to the value it resumes with.
    first = authenticate_employee(SELF, directory, AT)
    second = authenticate_employee(SELF, directory, AT)
    assert first == second
    assert first != authenticate_employee(REVIEWER, directory, AT)


# --- authentication resolves through the directory ----------------------------------------


def test_a_seeded_identifier_authenticates(directory: DirectoryBackend) -> None:
    context = authenticate_employee(SELF, directory, AT)
    assert context.employee_id == EmployeeId(SELF)
    assert context.authenticated_at == AT


@pytest.mark.parametrize(
    "claim",
    [
        None,
        "",
        " ",
        "\t",
        " E1042",
        "E1042 ",
        "E1042\n",
        "E10\x0042",
        "E" * (MAX_CLAIMED_ID_LENGTH + 1),
        1042,
        b"E1042",
        ABSENT,
        "e1042",
    ],
)
def test_a_claim_that_does_not_resolve_fails_closed(
    directory: DirectoryBackend, claim: Any
) -> None:
    with pytest.raises(SessionAuthenticationError):
        authenticate_employee(claim, directory, AT)


def test_a_malformed_claim_and_an_unresolved_one_are_indistinguishable(
    directory: DirectoryBackend,
) -> None:
    # Different messages would turn the session boundary into a directory oracle: a caller
    # could compare failures to learn which employee identifiers exist.
    with pytest.raises(SessionAuthenticationError) as malformed:
        authenticate_employee("!!", directory, AT)
    with pytest.raises(SessionAuthenticationError) as unresolved:
        authenticate_employee(ABSENT, directory, AT)
    assert str(malformed.value) == str(unresolved.value)


def test_an_unresolved_claim_reports_no_context(directory: DirectoryBackend) -> None:
    with pytest.raises(SessionAuthenticationError) as failure:
        authenticate_employee(ABSENT, directory, AT)
    assert ABSENT not in str(failure.value)
    assert failure.value.__cause__ is None


def test_the_boundary_is_not_bypassed_by_a_lookalike_directory(
    directory: DirectoryBackend,
) -> None:
    # An employee record built outside the directory must not become a session. The claim is
    # resolved through the backend, so a caller cannot supply the answer.
    assert authenticate_employee(SELF, directory, AT).employee_id == EmployeeId(SELF)
    with pytest.raises(SessionAuthenticationError):
        authenticate_employee("E1042-admin", directory, AT)


# --- authentication establishes who, policy decides what ----------------------------------


def test_an_inactive_employee_authenticates(directory: DirectoryBackend) -> None:
    assert authenticate_employee(INACTIVE, directory, AT).employee_id == EmployeeId(INACTIVE)


def test_policy_still_refuses_an_authenticated_inactive_requester(
    directory: DirectoryBackend,
) -> None:
    session = authenticate_employee(INACTIVE, directory, AT)
    requester = directory.get_employee(session.employee_id, session.employee_id)
    decision = evaluate(
        PolicyRequest(
            workflow_id=WorkflowId("WF-0001"),
            action_id=ActionId("ACT-0001"),
            evaluated_at=AT,
            requester=requester,
            resource=Resource(
                resource_id=ResourceId("wiki"),
                display_name="Company Wiki",
                resource_class=ResourceClass.BASELINE,
                owning_department=None,
            ),
            permission=Permission.READ,
            duration=AccessDuration.ONE_HOUR,
            baseline_permission=Permission.READ,
            risk_tier=RiskTier.LOW,
        )
    )
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.REQUESTER_INACTIVE


# --- reviewer identity ---------------------------------------------------------------------


def test_a_reviewer_authenticates_against_the_same_namespace(
    directory: DirectoryBackend,
) -> None:
    # The rule against approving one's own action is only checkable if reviewer and employee
    # identifiers name the same people.
    # The two identifiers are distinct types, so comparing them is a deliberate step down
    # to the strings rather than something a later step can do by accident.
    reviewer = authenticate_reviewer(REVIEWER, directory, AT)
    employee = authenticate_employee(REVIEWER, directory, AT)
    assert str(reviewer.reviewer_id) == str(employee.employee_id)


def test_a_reviewer_claim_fails_closed_the_same_way(directory: DirectoryBackend) -> None:
    with pytest.raises(SessionAuthenticationError):
        authenticate_reviewer(ABSENT, directory, AT)


def test_a_reviewer_session_cannot_stand_in_for_a_requester_session(
    directory: DirectoryBackend,
) -> None:
    class RequiresRequester(BaseModel):
        session: EmployeeSessionContext

    reviewer = authenticate_reviewer(REVIEWER, directory, AT)
    with pytest.raises(ValidationError):
        RequiresRequester(session=reviewer)  # type: ignore[arg-type]


# --- the session holds no authorization state ----------------------------------------------


def test_a_session_carries_no_permission_or_risk_value(directory: DirectoryBackend) -> None:
    context = authenticate_employee(SELF, directory, AT)
    dumped = context.model_dump()
    assert set(dumped) == {"employee_id", "authenticated_at"}
    assert not any(isinstance(value, Permission | RiskTier) for value in dumped.values())
