import pytest

from aegisdesk.backends.directory import DirectoryBackend
from aegisdesk.backends.seed import load_employees
from aegisdesk.domain.enums import Department
from aegisdesk.domain.errors import CrossEmployeeAccessError, UnknownEmployeeError
from aegisdesk.domain.ids import EmployeeId

SELF = EmployeeId("E1042")
OTHER = EmployeeId("E1043")
ABSENT = EmployeeId("E0000")


@pytest.fixture
def directory() -> DirectoryBackend:
    return DirectoryBackend(load_employees())


def test_employee_can_read_their_own_record(directory: DirectoryBackend) -> None:
    employee = directory.get_employee(SELF, SELF)
    assert employee.employee_id == SELF
    assert employee.department is Department.ENGINEERING


def test_reading_another_employees_record_is_denied(directory: DirectoryBackend) -> None:
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(SELF, OTHER)


def test_denial_does_not_reveal_whether_the_target_exists(directory: DirectoryBackend) -> None:
    # Both must fail the same way. Returning UnknownEmployeeError for a non-existent target
    # would let a caller enumerate the directory by comparing error types.
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(SELF, OTHER)
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(SELF, ABSENT)


def test_scoping_is_checked_before_existence(directory: DirectoryBackend) -> None:
    # Ordering matters: an existence check that ran first would leak membership through the
    # error type even though the final outcome is a denial either way.
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(ABSENT, OTHER)


def test_unknown_self_lookup_is_reported_as_unknown(directory: DirectoryBackend) -> None:
    with pytest.raises(UnknownEmployeeError):
        directory.get_employee(ABSENT, ABSENT)


def test_a_manager_cannot_read_a_direct_report(directory: DirectoryBackend) -> None:
    # No org-hierarchy exception exists. Any future exception must be an explicit,
    # authoritative rule rather than an implicit consequence of the reporting line.
    manager = EmployeeId("E1002")
    report = EmployeeId("E1042")
    assert directory.get_employee(report, report).manager_id == manager
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(manager, report)


def test_an_admin_role_grants_no_directory_exception(directory: DirectoryBackend) -> None:
    it_admin = EmployeeId("E1055")
    with pytest.raises(CrossEmployeeAccessError):
        directory.get_employee(it_admin, SELF)


def test_inactive_employees_are_returned_rather_than_hidden(directory: DirectoryBackend) -> None:
    # The directory reports state; deciding what an inactive requester may do belongs to
    # policy. Hiding the record here would make that decision unavailable.
    inactive = EmployeeId("E9099")
    assert directory.get_employee(inactive, inactive).is_active is False


def test_backend_is_isolated_from_the_mapping_it_was_given() -> None:
    employees = dict(load_employees())
    directory = DirectoryBackend(employees)
    employees.clear()
    assert directory.get_employee(SELF, SELF).employee_id == SELF
