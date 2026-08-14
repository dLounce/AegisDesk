from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.domain.enums import (
    DURATION_MAX_HOURS,
    AccessDuration,
    Permission,
    ProtectedOperation,
)
from aegisdesk.domain.errors import DomainInvariantError
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId


class AccessGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    employee_id: EmployeeId
    resource_id: ResourceId
    permission: Permission
    duration: AccessDuration
    granted_at: AwareDatetime
    expires_at: AwareDatetime | None
    # Every grant traces to the action that authorised it. A grant with no authorising
    # action is not representable, which keeps "who allowed this?" answerable from the
    # grant alone rather than from a reconstructed narrative.
    granted_via_action_id: ActionId

    @model_validator(mode="after")
    def _expiry_matches_duration(self) -> Self:
        is_time_boxed = DURATION_MAX_HOURS[self.duration] is not None
        if is_time_boxed and self.expires_at is None:
            raise DomainInvariantError(
                f"duration {self.duration.value} is time-boxed and requires expires_at"
            )
        if not is_time_boxed and self.expires_at is not None:
            raise DomainInvariantError(
                f"duration {self.duration.value} does not expire and forbids expires_at"
            )
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            raise DomainInvariantError("expires_at must be later than granted_at")
        return self


# What the access backend executes. The backend has no signature taking loose identifiers, so a
# grant to an employee nobody authorised cannot be spelled. This class is importable and a
# caller can therefore construct one, which is why constructing it is not what authorises
# anything: the backend also requires the minting key it issued to its single minting
# authority, and the guard claims that at construction.
class ExecutionReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: ActionId
    requester_id: EmployeeId
    resource_id: ResourceId
    permission: Permission
    duration: AccessDuration
    authorised_at: AwareDatetime


# What the access backend executes for a revoke or a modify, in the way ExecutionReceipt is for a
# grant. It carries no duration: a destructive change removes or re-points existing access rather
# than issuing a time-boxed one. `permission` is the named permission for a revoke and the target
# permission for a modify. Constructing one authorises nothing — the backend also requires the
# minting key, exactly as for a grant.
class DestructiveReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: ActionId
    operation: ProtectedOperation
    requester_id: EmployeeId
    resource_id: ResourceId
    permission: Permission
    authorised_at: AwareDatetime

    @model_validator(mode="after")
    def _operation_is_destructive(self) -> Self:
        if self.operation not in (
            ProtectedOperation.REVOKE_ACCESS,
            ProtectedOperation.MODIFY_PERMISSIONS,
        ):
            raise DomainInvariantError(f"{self.operation.value} is not a destructive operation")
        return self


# The recorded outcome of a destructive operation. A revoke leaves no permission, so
# resulting_permission is None; a modify re-points an existing permission, so both are present.
# It is what the backend returns and what a replay of a completed operation returns again, which
# is how a retried destructive execution stays exactly-once (S10 decision 9).
class AccessChange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: ProtectedOperation
    employee_id: EmployeeId
    resource_id: ResourceId
    previous_permission: Permission | None
    resulting_permission: Permission | None
    changed_at: AwareDatetime
    changed_via_action_id: ActionId

    @model_validator(mode="after")
    def _change_matches_operation(self) -> Self:
        if self.operation is ProtectedOperation.REVOKE_ACCESS:
            if self.previous_permission is None or self.resulting_permission is not None:
                raise DomainInvariantError("a revoke removes a held permission and leaves none")
        elif self.operation is ProtectedOperation.MODIFY_PERMISSIONS:
            if self.previous_permission is None or self.resulting_permission is None:
                raise DomainInvariantError("a modify re-points an existing permission to a new one")
        else:
            raise DomainInvariantError(f"{self.operation.value} does not produce an access change")
        return self
