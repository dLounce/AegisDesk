from collections.abc import Mapping

from aegisdesk.domain.employee import Employee
from aegisdesk.domain.errors import CrossEmployeeAccessError, UnknownEmployeeError
from aegisdesk.domain.ids import EmployeeId


class DirectoryBackend:
    def __init__(self, employees: Mapping[EmployeeId, Employee]) -> None:
        self._employees = dict(employees)

    # Both identities are required arguments so the backend can never be called without
    # stating who is asking. Scoping enforced here holds even if the agent, tool, or prompt
    # layer above it is compromised.
    def get_employee(self, requester_id: EmployeeId, target_id: EmployeeId) -> Employee:
        if requester_id != target_id:
            raise CrossEmployeeAccessError(
                f"requester {requester_id} may not read another employee's record"
            )
        employee = self._employees.get(target_id)
        if employee is None:
            raise UnknownEmployeeError(f"no directory record for {target_id}")
        return employee
