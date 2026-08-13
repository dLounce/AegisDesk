from collections.abc import Mapping

from aegisdesk.domain.employee import Employee
from aegisdesk.domain.enums import Permission
from aegisdesk.domain.errors import CrossEmployeeAccessError, UnknownEmployeeError
from aegisdesk.domain.ids import EmployeeId, ResourceId


class DirectoryBackend:
    def __init__(
        self,
        employees: Mapping[EmployeeId, Employee],
        baseline_access: Mapping[tuple[EmployeeId, ResourceId], Permission],
    ) -> None:
        self._employees = dict(employees)
        self._baseline_access = dict(baseline_access)

    # Both identities are required arguments so the backend can never be called without
    # stating who is asking. Scoping enforced here holds even if the agent, tool, or prompt
    # layer above it is compromised.
    def get_employee(self, requester_id: EmployeeId, target_id: EmployeeId) -> Employee:
        return self._self_scoped(requester_id, target_id)

    # project.md 10.3 lists baseline access among the authoritative employee context the
    # directory owns, so it is stored and returned here rather than derived from role or
    # department by any layer above. Absence is reported as None: policy treats no baseline as
    # no automatic access, so a pair this directory does not hold escalates instead of
    # resolving. An identifier with no catalogue entry is reported the same way, because
    # resource existence belongs to the catalogue and policy already refuses a request whose
    # resource did not resolve.
    def get_baseline_permission(
        self, requester_id: EmployeeId, target_id: EmployeeId, resource_id: ResourceId
    ) -> Permission | None:
        self._self_scoped(requester_id, target_id)
        return self._baseline_access.get((target_id, resource_id))

    # One scoping check for both reads. Two copies of a security check are how the two come to
    # disagree.
    def _self_scoped(self, requester_id: EmployeeId, target_id: EmployeeId) -> Employee:
        if requester_id != target_id:
            raise CrossEmployeeAccessError(
                f"requester {requester_id} may not read another employee's record"
            )
        employee = self._employees.get(target_id)
        if employee is None:
            raise UnknownEmployeeError(f"no directory record for {target_id}")
        return employee
