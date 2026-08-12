from pydantic import BaseModel, ConfigDict

from aegisdesk.domain.enums import Department, ResourceClass
from aegisdesk.domain.ids import ResourceId


class Resource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: ResourceId
    display_name: str
    resource_class: ResourceClass
    # Set for resources scoped to one department, None for company-wide resources. Policy
    # uses it to decide whether a requester is inside the resource's owning scope.
    owning_department: Department | None
