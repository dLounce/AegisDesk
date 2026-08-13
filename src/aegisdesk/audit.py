import hashlib
import secrets
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator

from aegisdesk.domain.enums import ActorType, AuditEventType, GuardOutcome
from aegisdesk.domain.ids import ActionId, AuditEventId, WorkflowId
from aegisdesk.policy import PolicyDecision

# Any untrusted string reaching a log is escaped and bounded here. A body or subject that
# carried a newline could otherwise forge a neighbouring log line, and a control character
# could rewrite a terminal reading the trail (ASVS V7.3.1). Escaping happens at the log
# boundary; the stored ticket and KB text are never mutated, in the same way the KB is never
# sanitised in place.
LOG_FIELD_MAX_LENGTH: Final = 256
_TRUNCATION_MARKER: Final = "..."


def sanitize_log_field(value: str) -> str:
    escaped: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            escaped.append("\\\\")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            escaped.append(f"\\x{code:02x}")
        else:
            escaped.append(ch)
    joined = "".join(escaped)
    if len(joined) > LOG_FIELD_MAX_LENGTH:
        return joined[:LOG_FIELD_MAX_LENGTH] + _TRUNCATION_MARKER
    return joined


_EVENT_DOMAIN: Final = b"aegisdesk.audit.v1"
EVENT_ID_HEX_LENGTH: Final = 32


# Derived for a correlated event, so a pre-pause pass replaying on resume produces the same
# identifier rather than a second row (AD-5). The three inputs are exactly the sink's
# idempotency key, so the identifier and the key stay in step.
def derive_event_id(
    event_type: AuditEventType, workflow_id: WorkflowId, action_id: ActionId
) -> AuditEventId:
    body = f"{event_type.value}\n{workflow_id}\n{action_id}".encode()
    digest = hashlib.sha256(_EVENT_DOMAIN + b"\n" + body).hexdigest()
    return AuditEventId(f"AEV-{digest[:EVENT_ID_HEX_LENGTH]}")


# For an event with no action identity — a pre-resolution refusal, a backend-side attempt — a
# fresh identifier per occurrence, because each genuine occurrence is its own audit line and
# there is no key under which to deduplicate it.
def _fresh_event_id() -> AuditEventId:
    return AuditEventId(f"AEV-{secrets.token_hex(EVENT_ID_HEX_LENGTH // 2)}")


# One append-only entry. Every field is either authoritative runtime state or a bounded, escaped
# descriptor: nothing a model wrote reaches the trail as prose. decision carries the whole
# validated PolicyDecision when there is one, so an entry is self-describing without a join, and
# is None for events reached before a decision exists.
class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: AuditEventId
    event_type: AuditEventType
    occurred_at: AwareDatetime
    actor_type: ActorType
    actor_id: str | None
    workflow_id: WorkflowId | None
    action_id: ActionId | None
    outcome: GuardOutcome | None
    refusal_reason: str | None
    decision: PolicyDecision | None
    detail: str | None

    # actor_id and detail are the two fields that can carry a caller-influenced string, so both
    # pass the log-boundary escaper. The remaining fields are enums, derived identifiers, or the
    # validated decision, none of which is free text.
    @field_validator("actor_id", "detail")
    @classmethod
    def _escape(cls, value: str | None) -> str | None:
        return None if value is None else sanitize_log_field(value)

    @classmethod
    def build(
        cls,
        *,
        event_type: AuditEventType,
        occurred_at: AwareDatetime,
        actor_type: ActorType,
        actor_id: str | None = None,
        workflow_id: WorkflowId | None = None,
        action_id: ActionId | None = None,
        outcome: GuardOutcome | None = None,
        refusal_reason: str | None = None,
        decision: PolicyDecision | None = None,
        detail: str | None = None,
    ) -> "AuditEvent":
        event_id = (
            derive_event_id(event_type, workflow_id, action_id)
            if workflow_id is not None and action_id is not None
            else _fresh_event_id()
        )
        return cls(
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            actor_type=actor_type,
            actor_id=actor_id,
            workflow_id=workflow_id,
            action_id=action_id,
            outcome=outcome,
            refusal_reason=refusal_reason,
            decision=decision,
            detail=detail,
        )

    # An event that names both a workflow and an action is idempotent under replay; one that does
    # not is appended on every occurrence. The key is the tuple the sink deduplicates on.
    def idempotency_key(self) -> tuple[WorkflowId, ActionId, AuditEventType] | None:
        if self.workflow_id is None or self.action_id is None:
            return None
        return (self.workflow_id, self.action_id, self.event_type)
