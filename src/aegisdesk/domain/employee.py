from pydantic import BaseModel, ConfigDict

from aegisdesk.domain.enums import Department, EmployeeRole
from aegisdesk.domain.ids import EmployeeId


class Employee(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    employee_id: EmployeeId
    display_name: str
    department: Department
    role: EmployeeRole
    manager_id: EmployeeId | None
    is_active: bool
