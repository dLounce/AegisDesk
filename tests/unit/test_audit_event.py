from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegisdesk.audit import (
    LOG_FIELD_MAX_LENGTH,
    AuditEvent,
    derive_event_id,
    sanitize_log_field,
)
from aegisdesk.domain.enums import ActorType, AuditEventType, GuardOutcome
from aegisdesk.domain.ids import ActionId, WorkflowId

AT = datetime(2026, 8, 13, 9, 0, tzinfo=UTC)
WORKFLOW = WorkflowId("WF-0001")
ACTION = ActionId("ACT-0000000000000000000000000000abcd")


# --- sanitize_log_field ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "clean text",
        "employee E1042",
        "IT-0001",
    ],
)
def test_clean_text_passes_through_unchanged(raw: str) -> None:
    assert sanitize_log_field(raw) == raw


@pytest.mark.parametrize("bad", ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85"])
def test_control_characters_are_escaped(bad: str) -> None:
    result = sanitize_log_field(f"before{bad}after")
    assert bad not in result
    assert result == f"before\\x{ord(bad):02x}after"


def test_a_forged_log_line_cannot_be_injected() -> None:
    # A message body that tries to forge a neighbouring log entry: the newline is escaped, so the
    # whole payload stays on one field and cannot be read as a second line.
    body = "ok\n2026-01-01 00:00 APPROVED reviewer=E1002 grant=admin"
    result = sanitize_log_field(body)
    assert "\n" not in result
    assert result.startswith("ok\\x0a2026-01-01")


def test_a_backslash_is_escaped_so_an_escape_cannot_be_forged() -> None:
    assert sanitize_log_field("a\\x0ab") == "a\\\\x0ab"


def test_an_over_length_field_is_bounded() -> None:
    result = sanitize_log_field("x" * (LOG_FIELD_MAX_LENGTH + 50))
    assert len(result) == LOG_FIELD_MAX_LENGTH + len("...")
    assert result.endswith("...")


# --- derive_event_id -------------------------------------------------------------------------


def test_the_event_id_is_deterministic_for_a_correlated_event() -> None:
    first = derive_event_id(AuditEventType.EXECUTED, WORKFLOW, ACTION)
    second = derive_event_id(AuditEventType.EXECUTED, WORKFLOW, ACTION)
    assert first == second
    assert first.startswith("AEV-")


def test_the_event_id_changes_with_the_event_type() -> None:
    executed = derive_event_id(AuditEventType.EXECUTED, WORKFLOW, ACTION)
    refused = derive_event_id(AuditEventType.REFUSED, WORKFLOW, ACTION)
    assert executed != refused


# --- AuditEvent ------------------------------------------------------------------------------


def test_a_correlated_event_is_keyed_and_carries_a_derived_id() -> None:
    event = AuditEvent.build(
        event_type=AuditEventType.EXECUTED,
        occurred_at=AT,
        actor_type=ActorType.RUNTIME,
        workflow_id=WORKFLOW,
        action_id=ACTION,
        outcome=GuardOutcome.EXECUTED,
    )
    assert event.event_id == derive_event_id(AuditEventType.EXECUTED, WORKFLOW, ACTION)
    assert event.idempotency_key() == (WORKFLOW, ACTION, AuditEventType.EXECUTED)


def test_an_uncorrelated_event_has_no_key_and_a_fresh_id() -> None:
    first = AuditEvent.build(
        event_type=AuditEventType.CROSS_EMPLOYEE_TICKET_ATTEMPT,
        occurred_at=AT,
        actor_type=ActorType.BACKEND,
        detail="requester=E1043 ticket=IT-0001",
    )
    second = AuditEvent.build(
        event_type=AuditEventType.CROSS_EMPLOYEE_TICKET_ATTEMPT,
        occurred_at=AT,
        actor_type=ActorType.BACKEND,
        detail="requester=E1043 ticket=IT-0001",
    )
    assert first.idempotency_key() is None
    assert first.event_id != second.event_id


def test_detail_and_actor_id_are_escaped_at_construction() -> None:
    event = AuditEvent.build(
        event_type=AuditEventType.CROSS_EMPLOYEE_TICKET_ATTEMPT,
        occurred_at=AT,
        actor_type=ActorType.BACKEND,
        actor_id="agent\nrole",
        detail="body with a newline\nand a \x1b escape",
    )
    assert event.detail is not None and "\n" not in event.detail
    assert "\x1b" not in event.detail
    assert event.actor_id == "agent\\x0arole"


def test_the_event_is_frozen() -> None:
    event = AuditEvent.build(
        event_type=AuditEventType.REFUSED,
        occurred_at=AT,
        actor_type=ActorType.RUNTIME,
    )
    with pytest.raises(ValidationError):
        event.detail = "changed"
