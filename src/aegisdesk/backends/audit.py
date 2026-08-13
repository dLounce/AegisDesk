from collections.abc import Sequence
from typing import Protocol

from aegisdesk.audit import AuditEvent
from aegisdesk.domain.enums import AuditEventType
from aegisdesk.domain.ids import ActionId, WorkflowId


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> AuditEvent: ...

    def events(self) -> Sequence[AuditEvent]: ...


# The append-only recording boundary. This is not durable non-repudiation: it holds the trail in
# process memory and a restart loses it. Durable, tamper-evident storage is a later persistence
# concern; what this class provides is the append-only shape and the replay idempotency the
# pause/resume path depends on.
class InMemoryAuditSink(AuditSink):
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._by_key: dict[tuple[WorkflowId, ActionId, AuditEventType], AuditEvent] = {}

    # Insert-if-absent under (workflow_id, action_id, event_type) for a correlated event, so the
    # pre-pause pass re-executing on resume records one entry rather than a duplicate (AD-5,
    # NON_NEGOTIABLES 6). An uncorrelated event has no key and is appended on every occurrence,
    # because a genuine repeat of a pre-resolution refusal or a cross-employee attempt is a
    # distinct line, not a replay of the same one.
    def record(self, event: AuditEvent) -> AuditEvent:
        key = event.idempotency_key()
        if key is not None:
            existing = self._by_key.get(key)
            if existing is not None:
                return existing
            self._by_key[key] = event
        self._events.append(event)
        return event

    # A tuple, so a caller cannot append to the trail through the value it was handed back.
    def events(self) -> Sequence[AuditEvent]:
        return tuple(self._events)
