from datetime import UTC, datetime

import pytest

from aegisdesk.backends.catalog import ResourceCatalog
from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import load_baseline_access, load_employees, load_resources
from aegisdesk.domain.enums import (
    AccessDuration,
    Permission,
    PolicyEffect,
    PolicyReason,
    ProtectedOperation,
    ResourceClass,
    RiskTier,
)
from aegisdesk.domain.errors import CrossEmployeeAccessError, UnknownEmployeeError
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId, WorkflowId
from aegisdesk.policy import PolicyRequest, evaluate
from aegisdesk.session import authenticate_employee

SELF = EmployeeId("E1042")
OTHER = EmployeeId("E1043")
ABSENT = EmployeeId("E0000")
INACTIVE = EmployeeId("E9099")

JIRA = ResourceId("jira")
FINANCE = ResourceId("finance-reports")
PROD_DB = ResourceId("prod-db")
UNCATALOGUED = ResourceId("prod-db-staging")

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)


@pytest.fixture
def directory() -> DirectoryBackend:
    return DirectoryBackend(load_employees(), load_baseline_access())


# --- the directory is the authoritative producer -------------------------------------------


def test_a_held_baseline_is_returned(directory: DirectoryBackend) -> None:
    assert directory.get_baseline_permission(SELF, SELF, JIRA) is Permission.WRITE


def test_a_resource_the_requester_does_not_hold_reports_no_baseline(
    directory: DirectoryBackend,
) -> None:
    assert directory.get_baseline_permission(SELF, SELF, FINANCE) is None


def test_a_resource_outside_the_catalogue_reports_no_baseline(
    directory: DirectoryBackend,
) -> None:
    # Resource existence belongs to the catalogue. Reporting it here would make the directory
    # a second answer to the same question, and policy already refuses an unresolved resource.
    assert directory.get_baseline_permission(SELF, SELF, UNCATALOGUED) is None


def test_no_privileged_resource_carries_a_baseline(directory: DirectoryBackend) -> None:
    catalogue = load_resources()
    for employee_id, resource_id in load_baseline_access():
        resource = catalogue[resource_id]
        assert resource.resource_class is not ResourceClass.PRIVILEGED, (
            f"{employee_id} holds a seeded baseline on privileged {resource_id}"
        )


# --- scoping and indistinguishable failure -------------------------------------------------


def test_reading_another_employees_baseline_is_denied(directory: DirectoryBackend) -> None:
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_baseline_permission(SELF, OTHER, JIRA)


def test_denial_does_not_reveal_whether_the_target_exists(
    directory: DirectoryBackend,
) -> None:
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_baseline_permission(SELF, OTHER, JIRA)
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_baseline_permission(SELF, ABSENT, JIRA)


def test_scoping_is_checked_before_existence(directory: DirectoryBackend) -> None:
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_baseline_permission(ABSENT, OTHER, JIRA)


def test_unknown_self_lookup_is_reported_as_unknown(directory: DirectoryBackend) -> None:
    with pytest.raises(UnknownEmployeeError):
        directory.get_baseline_permission(ABSENT, ABSENT, JIRA)


def test_both_reads_fail_the_same_way_for_the_same_call(
    directory: DirectoryBackend,
) -> None:
    # One scoping check serves both reads, so the two cannot come to disagree about who may
    # read what.
    with pytest.raises(CrossEmployeeAccessError) as record:
        directory.get_employee(SELF, OTHER)
    with pytest.raises(CrossEmployeeAccessError) as baseline:
        directory.get_baseline_permission(SELF, OTHER, JIRA)
    assert str(record.value) == str(baseline.value)


def test_backend_is_isolated_from_the_mapping_it_was_given() -> None:
    baseline = dict(load_baseline_access())
    directory = DirectoryBackend(load_employees(), baseline)
    baseline.clear()
    assert directory.get_baseline_permission(SELF, SELF, JIRA) is Permission.WRITE


# --- seed corpus integrity -----------------------------------------------------------------


def test_the_corpus_is_not_empty() -> None:
    assert load_baseline_access()


def test_every_seeded_pair_resolves() -> None:
    employees = load_employees()
    catalogue = load_resources()
    for employee_id, resource_id in load_baseline_access():
        assert employee_id in employees
        assert resource_id in catalogue


# --- the trusted path from session to policy -----------------------------------------------


def _request(
    requester_id: EmployeeId,
    resource_id: ResourceId,
    permission: Permission,
    directory: DirectoryBackend,
) -> PolicyRequest:
    return PolicyRequest(
        workflow_id=WorkflowId("WF-0001"),
        action_id=ActionId("ACT-0001"),
        evaluated_at=AT,
        operation=ProtectedOperation.GRANT_ACCESS,
        requester=directory.get_employee(requester_id, requester_id),
        resource=ResourceCatalog(load_resources()).get(resource_id),
        permission=permission,
        duration=AccessDuration.ONE_HOUR,
        baseline_permission=directory.get_baseline_permission(
            requester_id, requester_id, resource_id
        ),
        risk_tier=RiskTier.LOW,
    )


def test_a_request_within_the_directory_baseline_is_allowed(
    directory: DirectoryBackend,
) -> None:
    session = authenticate_employee("E1042", directory, AT)
    decision = evaluate(_request(session.employee_id, JIRA, Permission.READ, directory))
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.reason is PolicyReason.WITHIN_BASELINE


def test_a_request_above_the_directory_baseline_escalates(
    directory: DirectoryBackend,
) -> None:
    session = authenticate_employee("E1042", directory, AT)
    decision = evaluate(_request(session.employee_id, JIRA, Permission.ADMIN, directory))
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


def test_a_resource_with_no_directory_baseline_escalates(
    directory: DirectoryBackend,
) -> None:
    session = authenticate_employee("E1042", directory, AT)
    decision = evaluate(_request(session.employee_id, FINANCE, Permission.READ, directory))
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.EXCEEDS_BASELINE_PERMISSION


def test_a_privileged_resource_escalates_whatever_the_directory_holds(
    directory: DirectoryBackend,
) -> None:
    session = authenticate_employee("E1042", directory, AT)
    decision = evaluate(_request(session.employee_id, PROD_DB, Permission.READ, directory))
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.reason is PolicyReason.PRIVILEGED_RESOURCE


def test_an_inactive_requester_is_denied_despite_a_held_baseline(
    directory: DirectoryBackend,
) -> None:
    wiki = ResourceId("wiki")
    assert directory.get_baseline_permission(INACTIVE, INACTIVE, wiki) is Permission.READ
    decision = evaluate(_request(INACTIVE, wiki, Permission.READ, directory))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason is PolicyReason.REQUESTER_INACTIVE
