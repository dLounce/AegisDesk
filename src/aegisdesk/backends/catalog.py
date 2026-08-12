from collections.abc import Mapping

from aegisdesk.domain.errors import UnknownResourceError
from aegisdesk.domain.ids import ResourceId
from aegisdesk.domain.resource import Resource


class ResourceCatalog:
    def __init__(self, resources: Mapping[ResourceId, Resource]) -> None:
        self._resources = dict(resources)

    # Policy keys on the catalogue entry, never on a raw resource identifier chosen by a
    # model, so an unknown identifier fails closed here rather than being treated as an
    # unclassified resource further down.
    def get(self, resource_id: ResourceId) -> Resource:
        resource = self._resources.get(resource_id)
        if resource is None:
            raise UnknownResourceError(f"no catalogue entry for {resource_id}")
        return resource
