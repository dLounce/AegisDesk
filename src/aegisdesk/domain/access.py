from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from aegisdesk.domain.enums import DURATION_MAX_HOURS, AccessDuration, Permission
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
